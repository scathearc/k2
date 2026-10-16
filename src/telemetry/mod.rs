//! Telemetry engine: lock-free HDR histograms, status/error classifiers,
//! latency derivative, and the 100ms snapshot bus driving TUI / Web / controller.

pub mod derivative;
pub mod error_classifier;
pub mod histogram;

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;
use tokio::sync::watch;

use crate::error::ErrorKind;
use derivative::Deriv;
use error_classifier::{ClassifierState, WindowTotals};
use histogram::{Agg, AtomicHdr, HdrConfig};

pub const TICK_MS: u64 = 100;
pub const LAT_MIN_NS: u64 = 1;
pub const LAT_MAX_NS: u64 = 10_000_000_000_000;

/// Result of one executed request, anchor-stamped for coordinated-omission-free accounting.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub seq: u64,
    pub intended_send: Instant,
    pub actual_start: Instant,
    pub completed: Instant,
    pub status: Option<u16>,
    pub error: Option<ErrorKind>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl Outcome {
    /// Coordinated-omission-corrected latency: completion anchored to the
    /// intended dispatch time, not the actual (delayed) one.
    #[inline]
    pub fn latency_ns(&self) -> u64 {
        let d = self.completed.saturating_duration_since(self.intended_send);
        d.as_nanos().min(u64::MAX as u128) as u64
    }
    /// Worker dispatch lag: how late execution started vs. intent.
    #[inline]
    pub fn dispatch_lag_ns(&self) -> u64 {
        let d = self
            .actual_start
            .saturating_duration_since(self.intended_send);
        d.as_nanos().min(u64::MAX as u128) as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Trend {
    Stable,
    Degrading,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct HistPoint {
    pub ms: u64,
    pub p99_ns: u64,
    pub rps: f64,
    pub err_pct: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub tick_ms: u64,
    pub running: bool,
    pub elapsed_s: f64,
    pub count_total: u64,
    pub dispatched: u64,
    pub count_window: u64,
    pub in_flight: u64,
    pub target_rate: f64,
    pub actual_rps: f64,
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub mean_ns: u64,
    pub dlat_dt: f64,
    pub dlat_rel: f64,
    pub trend: Trend,
    pub statuses: Vec<(u16, u64, f64)>,
    pub errors: Vec<(ErrorKind, u64)>,
    pub err_window: u64,
    pub err_pct_window: f64,
    pub bytes_in_total: u64,
    pub bytes_per_s: f64,
    pub scheduler_lag_p99_ns: u64,
    pub ws_held: u64,
    pub strategy: String,
    pub history: Vec<HistPoint>,
}

impl Snapshot {
    pub fn idle() -> Self {
        Self {
            tick_ms: 0,
            running: false,
            elapsed_s: 0.0,
            count_total: 0,
            dispatched: 0,
            count_window: 0,
            in_flight: 0,
            target_rate: 0.0,
            actual_rps: 0.0,
            p50_ns: 0,
            p90_ns: 0,
            p95_ns: 0,
            p99_ns: 0,
            mean_ns: 0,
            dlat_dt: 0.0,
            dlat_rel: 0.0,
            trend: Trend::Idle,
            statuses: vec![],
            errors: vec![],
            err_window: 0,
            err_pct_window: 0.0,
            bytes_in_total: 0,
            bytes_per_s: 0.0,
            scheduler_lag_p99_ns: 0,
            ws_held: 0,
            strategy: "starting".into(),
            history: vec![],
        }
    }
}

struct Cum {
    lat: Agg,
    lag: Agg,
}

/// Window drain data returned by `begin_tick` and finished by `finish_tick`.
pub struct TickData {
    pub lat_window: Vec<u64>,
    pub lag_window: Vec<u64>,
    pub window: WindowTotals,
}

/// Central telemetry recorder + 100ms tick aggregator.
pub struct Telemetry {
    started: Instant,
    lat: AtomicHdr,
    lag: AtomicHdr,
    cum: Mutex<Cum>,
    cls: ClassifierState,
    total_count: AtomicU64,
    window_ring: Mutex<VecDeque<u64>>,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    ws_held: AtomicI64,
    in_flight: AtomicI64,
    dispatched: AtomicU64,
    target_rate: AtomicU64,
    strategy_label: Mutex<String>,
    deriv: Mutex<Deriv>,
    history: Mutex<VecDeque<HistPoint>>,
    tx: watch::Sender<Snapshot>,
    pub rx: watch::Receiver<Snapshot>,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl Telemetry {
    pub fn new() -> Self {
        let lat_cfg = HdrConfig::new(LAT_MIN_NS, LAT_MAX_NS);
        let (tx, rx) = watch::channel(Snapshot::idle());
        Self {
            started: Instant::now(),
            lat: AtomicHdr::new(LAT_MIN_NS, LAT_MAX_NS),
            lag: AtomicHdr::new(LAT_MIN_NS, LAT_MAX_NS),
            cum: Mutex::new(Cum {
                lat: Agg::empty(lat_cfg),
                lag: Agg::empty(lat_cfg),
            }),
            cls: ClassifierState::new(),
            total_count: AtomicU64::new(0),
            window_ring: Mutex::new(VecDeque::with_capacity(11)),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            ws_held: AtomicI64::new(0),
            in_flight: AtomicI64::new(0),
            dispatched: AtomicU64::new(0),
            target_rate: AtomicU64::new(0),
            strategy_label: Mutex::new("starting".into()),
            deriv: Mutex::new(Deriv::new(6)),
            history: Mutex::new(VecDeque::with_capacity(241)),
            tx,
            rx,
        }
    }

    pub fn started(&self) -> Instant {
        self.started
    }

    #[inline]
    pub fn enter_flight(&self) {
        let _ = self.in_flight.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn exit_flight(&self) {
        let _ = self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn dispatched_inc(&self) {
        let _ = self.dispatched.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn ws_held_inc(&self) {
        let _ = self.ws_held.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn ws_held_dec(&self) {
        let _ = self.ws_held.fetch_sub(1, Ordering::Relaxed);
    }
    pub fn ws_held(&self) -> u64 {
        self.ws_held.load(Ordering::Relaxed).max(0) as u64
    }
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed).max(0) as u64
    }
    #[inline]
    pub fn set_target_rate(&self, r: f64) {
        self.target_rate
            .store(r.clamp(0.0, u64::MAX as f64) as u64, Ordering::Relaxed);
    }
    pub fn set_strategy_label(&self, s: impl Into<String>) {
        *self.strategy_label.lock().unwrap() = s.into();
    }
    pub fn target_rate(&self) -> f64 {
        self.target_rate.load(Ordering::Relaxed) as f64
    }
    pub fn dispatched(&self) -> u64 {
        self.dispatched.load(Ordering::Relaxed)
    }
    pub fn count_total(&self) -> u64 {
        self.total_count.load(Ordering::Relaxed)
    }

    /// Record one completed request (per flight end).
    #[inline]
    pub fn record(&self, o: &Outcome) {
        let _ = self.total_count.fetch_add(1, Ordering::Relaxed);
        match (o.status, o.error) {
            (Some(code), None) => {
                self.lat.record(o.latency_ns());
                self.cls.record_status(code);
            }
            (_, Some(kind)) => {
                self.lat.record(o.latency_ns());
                self.cls.record_error(kind);
            }
            // Neither: a cancelled dispatch; counts as a window event only.
            (None, None) => {
                self.lat.record(o.latency_ns());
                self.cls.record_error(ErrorKind::Cancelled);
            }
        }
        self.lag.record(o.dispatch_lag_ns());
        self.bytes_in.fetch_add(o.bytes_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(o.bytes_out, Ordering::Relaxed);
    }

    /// Record + close the flight in one call.
    #[inline]
    pub fn record_flight_end(&self, o: &Outcome) {
        self.record(o);
        self.exit_flight();
    }

    /// Begin a tick: atomically drain the 100ms window.
    pub fn begin_tick(&self) -> TickData {
        let lat_window = self.lat.drain();
        let lag_window = self.lag.drain();
        let window = self.cls.drain_window();
        TickData {
            lat_window,
            lag_window,
            window,
        }
    }

    /// p99 of a drained window's latency counts (controller input).
    pub fn window_p99_of(&self, td: &TickData) -> f64 {
        let a = agg_from(&td.lat_window);
        a.quantile(0.99).unwrap_or(0) as f64
    }

    /// Finish a tick: merge into cumulative aggregates, derive dLat/dt, publish snapshot.
    pub fn finish_tick(&self, td: TickData) -> Snapshot {
        let now = Instant::now();
        let tick_ms = now.saturating_duration_since(self.started).as_millis() as u64;

        {
            let mut cum = self.cum.lock().unwrap();
            cum.lat.add_bucket(&td.lat_window);
            cum.lag.add_bucket(&td.lag_window);
        }

        let (cum_lat, cum_lag, status_map, err_map) = {
            let cum = self.cum.lock().unwrap();
            (
                cum.lat.clone(),
                cum.lag.clone(),
                self.cls.status_map(),
                self.cls.error_map(),
            )
        };

        let total_count = self.total_count.load(Ordering::Relaxed);
        let dispatched = self.dispatched.load(Ordering::Relaxed);
        let in_flight = self.in_flight.load(Ordering::Relaxed).max(0) as u64;
        let target_rate = self.target_rate();
        let bytes_in_total = self.bytes_in.load(Ordering::Relaxed);
        let ws_held = self.ws_held();

        // 1s RPS: mean of the last up-to-10 window counts.
        let actual_rps = {
            let mut g = self.window_ring.lock().unwrap();
            g.push_back(td.window.count);
            if g.len() > 10 {
                g.pop_front();
            }
            let len = g.len().max(1);
            g.iter().sum::<u64>() as f64 * (10.0 / len as f64)
        };

        // Window p99 straight from the freshly drained window counts.
        let win_lat_agg = agg_from(&td.lat_window);
        let window_p99 = win_lat_agg.quantile(0.99).unwrap_or(0) as f64;

        // Derivative on window p99; errors force the Degrading verdict.
        let (dlat_dt, dlat_rel, trend) = {
            let mut d = self.deriv.lock().unwrap();
            d.push(tick_ms, window_p99);
            let err_rate = if td.window.count > 0 {
                td.window.errors as f64 / td.window.count as f64
            } else if td.window.errors > 0 {
                1.0
            } else {
                0.0
            };
            let degrading = d.is_degrading(0.35, err_rate);
            let trend = if total_count == 0 {
                Trend::Idle
            } else if degrading {
                Trend::Degrading
            } else {
                Trend::Stable
            };
            (d.slope(), d.relative(), trend)
        };

        let statuses: Vec<(u16, u64, f64)> = status_map
            .iter()
            .map(|(c, n)| {
                let pct = if total_count > 0 {
                    (*n as f64) * 100.0 / total_count as f64
                } else {
                    0.0
                };
                (*c, *n, pct)
            })
            .collect();
        let errors = err_map;
        let err_pct_window = if td.window.count + td.window.errors > 0 {
            (td.window.errors as f64) * 100.0 / ((td.window.count + td.window.errors) as f64)
        } else {
            0.0
        };

        let history = {
            let mut h = self.history.lock().unwrap();
            h.push_back(HistPoint {
                ms: tick_ms,
                p99_ns: window_p99 as u64,
                rps: td.window.count as f64 * 10.0,
                err_pct: err_pct_window,
            });
            while h.len() > 240 {
                h.pop_front();
            }
            h.iter().copied().collect()
        };

        let elapsed_s = now.saturating_duration_since(self.started).as_secs_f64();

        let snap = Snapshot {
            tick_ms,
            running: true,
            elapsed_s,
            count_total: total_count,
            dispatched,
            count_window: td.window.count,
            in_flight,
            target_rate,
            actual_rps,
            p50_ns: cum_lat.quantile(0.50).unwrap_or(0),
            p90_ns: cum_lat.quantile(0.90).unwrap_or(0),
            p95_ns: cum_lat.quantile(0.95).unwrap_or(0),
            p99_ns: cum_lat.quantile(0.99).unwrap_or(0),
            mean_ns: cum_lat.mean().unwrap_or(0.0) as u64,
            dlat_dt,
            dlat_rel,
            trend,
            statuses,
            errors,
            err_window: td.window.errors,
            err_pct_window,
            bytes_in_total,
            bytes_per_s: if elapsed_s > 0.0 {
                bytes_in_total as f64 / elapsed_s
            } else {
                0.0
            },
            scheduler_lag_p99_ns: cum_lag.quantile(0.99).unwrap_or(0),
            ws_held,
            strategy: self.strategy_label.lock().unwrap().clone(),
            history,
        };
        self.tx.send_replace(snap.clone());
        snap
    }

    /// Final aggregate of the whole run (cumulative + any post-tick stragglers).
    pub fn aggregate(&self) -> (Agg, Agg) {
        let lat_final = self.lat.drain();
        let lag_final = self.lag.drain();
        let mut cum = self.cum.lock().unwrap();
        cum.lat.add_bucket(&lat_final);
        cum.lag.add_bucket(&lag_final);
        (cum.lat.clone(), cum.lag.clone())
    }

    pub fn cumulative_maps(
        &self,
    ) -> (
        error_classifier::StatusCounts,
        error_classifier::ErrorCounts,
        u64,
        u64,
        u64,
    ) {
        let statuses = self.cls.status_map();
        let errors = self.cls.error_map();
        let bytes_in = self.bytes_in.load(Ordering::Relaxed);
        let bytes_out = self.bytes_out.load(Ordering::Relaxed);
        let ws = self.ws_held();
        (statuses, errors, bytes_in, bytes_out, ws)
    }

    /// Node-mode ingest payload for the swarm coordinator: cumulative buckets
    /// (merge = sum across nodes), maps, and counters.
    pub fn ingest_payload(&self, node: u64) -> crate::swarm::ingest::IngestPayload {
        let (lat_cum, lag_cum) = {
            let cum = self.cum.lock().unwrap();
            (cum.lat.counts.clone(), cum.lag.counts.clone())
        };
        let statuses = self.cls.status_map();
        let errors = self.cls.error_map();
        crate::swarm::ingest::IngestPayload {
            node,
            done: false,
            count_total: self.total_count.load(Ordering::Relaxed),
            dispatched: self.dispatched(),
            in_flight: self.in_flight(),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            ws_held: self.ws_held(),
            status_map: statuses,
            error_map: errors,
            lat_cum,
            lag_cum,
            ws: None,
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        self.rx.borrow().clone()
    }
}

fn agg_from(counts: &[u64]) -> Agg {
    Agg {
        cfg: HdrConfig::new(LAT_MIN_NS, LAT_MAX_NS),
        counts: counts.to_vec(),
        total: counts.iter().sum(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn outcome(lat: Duration) -> Outcome {
        let intended = Instant::now();
        let start = intended + Duration::from_millis(3);
        Outcome {
            seq: 1,
            intended_send: intended,
            actual_start: start,
            completed: start + lat,
            status: Some(200),
            error: None,
            bytes_in: 10,
            bytes_out: 5,
        }
    }

    #[tokio::test]
    async fn records_and_aggregates() {
        let t = Telemetry::new();
        for _ in 0..100 {
            let o = outcome(Duration::from_millis(10));
            t.enter_flight();
            t.record_flight_end(&o);
        }
        let snap = t.finish_tick(t.begin_tick());
        assert_eq!(snap.count_total, 100);
        assert_eq!(snap.count_window, 100);
        assert_eq!(snap.statuses[0], (200, 100, 100.0));
        assert_eq!(snap.errors.len(), 0);
        // CO correction: latency anchored to intended dispatch (10ms + 3ms lag)
        assert!(snap.p50_ns >= 12_900_000, "p50 {}", snap.p50_ns);
        assert!(
            snap.mean_ns >= 12_500_000 && snap.mean_ns <= 14_000_000,
            "mean {}",
            snap.mean_ns
        );
        assert!(snap.scheduler_lag_p99_ns >= 2_900_000);
        t.aggregate();
    }

    #[tokio::test]
    async fn error_window_shows_in_trend() {
        let t = Telemetry::new();
        let intended = Instant::now();
        let o = Outcome {
            seq: 1,
            intended_send: intended,
            actual_start: intended,
            completed: intended + Duration::from_millis(1),
            status: None,
            error: Some(ErrorKind::Timeout),
            bytes_in: 0,
            bytes_out: 0,
        };
        for _ in 0..5 {
            t.enter_flight();
            t.record_flight_end(&o);
        }
        let snap = t.finish_tick(t.begin_tick());
        assert_eq!(snap.trend, Trend::Degrading);
        assert_eq!(snap.errors[0].0, ErrorKind::Timeout);
    }

    #[tokio::test]
    async fn one_second_rps_estimates_from_window_ring() {
        let t = Telemetry::new();
        for _ in 0..50 {
            let o = outcome(Duration::from_millis(1));
            t.enter_flight();
            t.record_flight_end(&o);
        }
        let snap = t.finish_tick(t.begin_tick());
        assert!(
            (snap.actual_rps - 500.0).abs() < 5.0,
            "rps {}",
            snap.actual_rps
        );
    }

    #[tokio::test]
    async fn idle_snapshot_is_idle() {
        let t = Telemetry::new();
        let snap = t.finish_tick(t.begin_tick());
        assert_eq!(snap.trend, Trend::Idle);
        assert_eq!(snap.count_total, 0);
    }
}
