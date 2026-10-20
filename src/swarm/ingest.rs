//! Swarm ingest: the wire payload nodes report and the coordinator's merge
//! store (bucket-exact histogram merging — the payoff of the hand-rolled HDR).
//!
//! Nodes report *cumulative* buckets; the coordinator keeps each node's
//! previous snapshot and derives per-poll window deltas by subtraction, which
//! survive missed polls without double-counting.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::ErrorKind;
use crate::telemetry::error_classifier::WindowTotals;
use crate::telemetry::histogram::{Agg, HdrConfig};

/// Wire payload: node telemetry to the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IngestPayload {
    pub node: u64,
    /// Set on the node's final report after a drain.
    #[serde(default)]
    pub done: bool,
    #[serde(default)]
    pub count_total: u64,
    #[serde(default)]
    pub dispatched: u64,
    #[serde(default)]
    pub in_flight: u64,
    #[serde(default)]
    pub bytes_in: u64,
    #[serde(default)]
    pub bytes_out: u64,
    #[serde(default)]
    pub ws_held: u64,
    #[serde(default)]
    pub status_map: Vec<(u16, u64)>,
    #[serde(default)]
    pub error_map: Vec<(ErrorKind, u64)>,
    /// Cumulative HDR bucket counts (config-compatible across nodes).
    #[serde(default)]
    pub lat_cum: Vec<u64>,
    #[serde(default)]
    pub lag_cum: Vec<u64>,
    #[serde(default)]
    pub ws: Option<crate::engine::ws::WsStats>,
}

/// Window delta accumulated across polls; drained by the controller tick.
#[derive(Debug, Default, Clone)]
pub struct WindowDelta {
    pub count: u64,
    pub errors: u64,
    pub bad_status: u64,
    pub s403: u64,
    pub s405: u64,
    pub win_lat: Vec<u64>,
}

#[derive(Debug)]
struct NodeSlot {
    count_total: u64,
    dispatched: u64,
    bytes_in: u64,
    bytes_out: u64,
    in_flight: u64,
    ws_held: u64,
    statuses: HashMap<u16, u64>,
    errors: HashMap<ErrorKind, u64>,
    lat_cum: Vec<u64>,
    lag_cum: Vec<u64>,
    ws: Option<crate::engine::ws::WsStats>,
    done: bool,
}

/// Sum of status codes >= 400 (the status-first degradation family).
fn bad_status_total(m: &std::collections::HashMap<u16, u64>) -> u64 {
    let mut s = 0u64;
    for (c, n) in m {
        if usize::from(*c) >= 400 {
            s += *n;
        }
    }
    s
}

fn slot_from(p: &IngestPayload) -> NodeSlot {
    NodeSlot {
        count_total: p.count_total,
        dispatched: p.dispatched,
        bytes_in: p.bytes_in,
        bytes_out: p.bytes_out,
        in_flight: p.in_flight,
        ws_held: p.ws_held,
        statuses: p.status_map.iter().copied().collect(),
        errors: p.error_map.iter().cloned().collect(),
        lat_cum: p.lat_cum.clone(),
        lag_cum: p.lag_cum.clone(),
        ws: p.ws.clone(),
        done: p.done,
    }
}

/// Cheap merged cumulative view for the display bus.
#[derive(Debug, Default, Clone)]
pub struct MergedDisplay {
    pub lat_counts: Vec<u64>,
    pub lag_counts: Vec<u64>,
    pub statuses: Vec<(u16, u64)>,
    pub errors: Vec<(ErrorKind, u64)>,
    pub count_total: u64,
    pub dispatched: u64,
    pub in_flight: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub ws_held: u64,
}

/// Coordinator-side merge store.
#[derive(Debug)]
pub struct MergeStore {
    inner: Mutex<MergeInner>,
    lat_cfg: HdrConfig,
    /// Accumulated window deltas since the last controller drain.
    window: Mutex<WindowDelta>,
}

#[derive(Debug, Default)]
struct MergeInner {
    nodes: HashMap<u64, NodeSlot>,
}

impl MergeStore {
    pub fn new(lat_cfg: HdrConfig) -> Self {
        let buckets = lat_cfg.n_buckets();
        Self {
            inner: Mutex::new(MergeInner::default()),
            lat_cfg,
            window: Mutex::new(WindowDelta {
                win_lat: vec![0; buckets],
                ..Default::default()
            }),
        }
    }

    pub fn node_count(&self) -> usize {
        self.inner.lock().unwrap().nodes.len()
    }

    pub fn all_done(&self) -> bool {
        let g = self.inner.lock().unwrap();
        !g.nodes.is_empty() && g.nodes.values().all(|s| s.done)
    }

    pub fn any_done(&self) -> bool {
        let g = self.inner.lock().unwrap();
        g.nodes.values().any(|s| s.done)
    }

    pub fn in_flight_total(&self) -> u64 {
        let g = self.inner.lock().unwrap();
        g.nodes.values().map(|s| s.in_flight).sum()
    }

    /// Replace a node's slot; accumulate the delta into the controller window.
    pub fn update(&self, p: IngestPayload) {
        let buckets = self.lat_cfg.n_buckets();
        let mut g = self.inner.lock().unwrap();
        let delta = |prev: u64, cur: u64| cur.saturating_sub(prev);
        let mut wd = WindowDelta::default();

        if let Some(slot) = g.nodes.get(&p.node) {
            wd.count = delta(slot.count_total, p.count_total);
            wd.errors = delta(
                slot.errors.values().sum(),
                p.error_map.iter().map(|(_, n)| n).sum(),
            );
            let prev_bad = bad_status_total(&slot.statuses);
            let cur_bad = bad_status_total(&p.status_map.iter().copied().collect());
            wd.bad_status = cur_bad.saturating_sub(prev_bad);
            wd.s403 = delta(
                slot.statuses.get(&403).copied().unwrap_or(0),
                p.status_map
                    .iter()
                    .find(|(c, _)| *c == 403)
                    .map(|(_, n)| *n)
                    .unwrap_or(0),
            );
            let mut win_lat = vec![0u64; buckets];
            for (i, (cur, prev)) in p
                .lat_cum
                .iter()
                .zip(slot.lat_cum.iter())
                .enumerate()
                .take(buckets)
            {
                win_lat[i] = cur.saturating_sub(*prev);
            }
            wd.win_lat = win_lat;
        } else {
            // First sight of the node: its whole history is the delta.
            wd.count = p.count_total;
            wd.errors = p.error_map.iter().map(|(_, n)| n).sum();
            wd.bad_status = p
                .status_map
                .iter()
                .filter(|(c, _)| usize::from(*c) >= 400)
                .map(|(_, n)| n)
                .sum();
            wd.s403 = p
                .status_map
                .iter()
                .find(|(c, _)| *c == 403)
                .map(|(_, n)| *n)
                .unwrap_or(0);
            let mut win_lat = vec![0u64; buckets];
            for (i, c) in p.lat_cum.iter().take(buckets).enumerate() {
                win_lat[i] = *c;
            }
            wd.win_lat = win_lat;
        }

        g.nodes.insert(p.node, slot_from(&p));
        drop(g);
        let mut w = self.window.lock().unwrap();
        w.count += wd.count;
        w.errors += wd.errors;
        w.bad_status += wd.bad_status;
        w.s403 += wd.s403;
        w.s405 += wd.s405;
        for (i, c) in wd.win_lat.iter().enumerate() {
            w.win_lat[i] += c;
        }
    }

    /// Drain the accumulated window for the controller tick. Returns the
    /// tallies plus the window's merged latency buckets (same-tick data —
    /// the caller derives the window p99 from them, mirroring how a local
    /// run computes p99 from its own drained window).
    pub fn drain_window(&self) -> (WindowTotals, Vec<u64>) {
        let mut w = self.window.lock().unwrap();
        let wt = WindowTotals {
            count: std::mem::take(&mut w.count),
            errors: std::mem::take(&mut w.errors),
            bad_status: std::mem::take(&mut w.bad_status),
            s403: std::mem::take(&mut w.s403),
            s405: std::mem::take(&mut w.s405),
            ..Default::default()
        };
        let win_lat = std::mem::replace(&mut w.win_lat, vec![0; self.lat_cfg.n_buckets()]);
        (wt, win_lat)
    }

    /// Merged cumulative view for the coordinator's display bus (TUI/web).
    /// Cheap: clones bucket vecs and maps; called at 100ms cadence.
    pub fn merged_display(&self) -> MergedDisplay {
        let buckets = self.lat_cfg.n_buckets();
        let g = self.inner.lock().unwrap();
        let mut d = MergedDisplay {
            lat_counts: vec![0; buckets],
            lag_counts: vec![0; buckets],
            ..Default::default()
        };
        let mut statuses: HashMap<u16, u64> = HashMap::new();
        let mut errors: HashMap<ErrorKind, u64> = HashMap::new();
        for slot in g.nodes.values() {
            if slot.lat_cum.len() == buckets {
                for (i, c) in slot.lat_cum.iter().enumerate() {
                    d.lat_counts[i] += c;
                }
            }
            if slot.lag_cum.len() == buckets {
                for (i, c) in slot.lag_cum.iter().enumerate() {
                    d.lag_counts[i] += c;
                }
            }
            for (c, n) in &slot.statuses {
                *statuses.entry(*c).or_default() += n;
            }
            for (k, n) in &slot.errors {
                *errors.entry(*k).or_default() += n;
            }
            d.count_total += slot.count_total;
            d.dispatched += slot.dispatched;
            d.in_flight += slot.in_flight;
            d.bytes_in += slot.bytes_in;
            d.bytes_out += slot.bytes_out;
            d.ws_held += slot.ws_held;
        }
        d.statuses = statuses.into_iter().collect();
        d.errors = errors.into_iter().collect();
        d
    }

    /// Final merged cumulative state for the report: (lat, lag, statuses,
    /// errors, count_total, dispatched, bytes_in, bytes_out, ws).
    #[allow(clippy::type_complexity)]
    pub fn merged_final(
        &self,
    ) -> (
        Agg,
        Agg,
        Vec<(u16, u64)>,
        Vec<(ErrorKind, u64)>,
        u64,
        u64,
        u64,
        u64,
        Option<crate::engine::ws::WsStats>,
    ) {
        let g = self.inner.lock().unwrap();
        let mut lat = Agg::empty(self.lat_cfg);
        let mut lag = Agg::empty(self.lat_cfg);
        let mut statuses: HashMap<u16, u64> = HashMap::new();
        let mut errors: HashMap<ErrorKind, u64> = HashMap::new();
        let mut count_total = 0u64;
        let mut dispatched = 0u64;
        let mut bytes_in = 0u64;
        let mut bytes_out = 0u64;
        let mut ws: Option<crate::engine::ws::WsStats> = None;
        for slot in g.nodes.values() {
            if slot.lat_cum.len() == lat.counts.len() {
                for (i, c) in slot.lat_cum.iter().enumerate() {
                    lat.counts[i] += c;
                }
            }
            if slot.lag_cum.len() == lag.counts.len() {
                for (i, c) in slot.lag_cum.iter().enumerate() {
                    lag.counts[i] += c;
                }
            }
            for (c, n) in &slot.statuses {
                *statuses.entry(*c).or_default() += n;
            }
            for (k, n) in &slot.errors {
                *errors.entry(*k).or_default() += n;
            }
            count_total += slot.count_total;
            dispatched += slot.dispatched;
            bytes_in += slot.bytes_in;
            bytes_out += slot.bytes_out;
            if let Some(s) = &slot.ws {
                ws = Some(match ws {
                    None => s.clone(),
                    Some(mut acc) => {
                        acc.opened += s.opened;
                        acc.closed += s.closed;
                        acc.failed += s.failed;
                        acc.sent += s.sent;
                        acc.frames_rx += s.frames_rx;
                        acc.bytes_rx += s.bytes_rx;
                        acc.bytes_tx += s.bytes_tx;
                        acc
                    }
                });
            }
        }
        lat.recount();
        lag.recount();
        (
            lat,
            lag,
            statuses.into_iter().collect(),
            errors.into_iter().collect(),
            count_total,
            dispatched,
            bytes_in,
            bytes_out,
            ws,
        )
    }
}
