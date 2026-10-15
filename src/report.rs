//! Final run report: text + JSON.

use std::time::Duration;

use serde::Serialize;

use crate::engine::ws::WsStats;
use crate::telemetry::histogram::Agg;

#[derive(Debug, Clone, Serialize, Default)]
pub struct StatusLine {
    pub code: u16,
    pub count: u64,
    pub pct: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ErrorLine {
    pub kind: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct LatencyBlock {
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub mean_ms: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct RunReport {
    pub target: String,
    pub strategy: String,
    pub runtime_s: f64,
    pub requests_sent: u64,
    pub responses: u64,
    pub target_rps: f64,
    pub actual_rps: f64,
    pub statuses: Vec<StatusLine>,
    pub errors: Vec<ErrorLine>,
    pub latency: LatencyBlock,
    pub scheduler_lag_p99_ms: f64,
    pub bytes_in: u64,
    pub bytes_per_s: f64,
    pub bytes_out: u64,
    pub ws: Option<WsStats>,
    pub ws_held: u64,
    pub coordinated_omission_corrected: bool,
    pub fidelity: String,
    pub http_version: String,
    pub proxy: Option<String>,
    pub mutation_active: String,
}

impl RunReport {
    pub fn failure_rate(&self) -> f64 {
        let errs: u64 = self.errors.iter().map(|e| e.count).sum();
        let total = errs + self.responses;
        if total == 0 {
            0.0
        } else {
            errs as f64 / total as f64
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }
}

/// Plain-text summary.
pub fn render_text(r: &RunReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "K2 run report");
    let _ = writeln!(out, "  target           : {}", r.target);
    let _ = writeln!(out, "  strategy         : {}", r.strategy);
    let _ = writeln!(out, "  runtime          : {:.2}s", r.runtime_s);
    let _ = writeln!(out, "  requests         : {}", r.requests_sent);
    let _ = writeln!(out, "  responses        : {}", r.responses);
    let _ = writeln!(
        out,
        "  throughput       : target {:.0}/s actual {:.0}/s",
        r.target_rps, r.actual_rps
    );
    if !r.statuses.is_empty() {
        let _ = writeln!(out, "  status:");
        for s in &r.statuses {
            let _ = writeln!(out, "    {:>3}: {:>10}  ({:.1}%)", s.code, s.count, s.pct);
        }
    }
    if !r.errors.is_empty() {
        let _ = writeln!(out, "  transport errors:");
        for e in &r.errors {
            let _ = writeln!(out, "     {:<8}: {:>10}", e.kind, e.count);
        }
    }
    let _ = writeln!(out, "  latency (CO-corrected):");
    let _ = writeln!(out, "    p50  : {:.2} ms", r.latency.p50_ms);
    let _ = writeln!(out, "    p90  : {:.2} ms", r.latency.p90_ms);
    let _ = writeln!(out, "    p95  : {:.2} ms", r.latency.p95_ms);
    let _ = writeln!(out, "    p99  : {:.2} ms", r.latency.p99_ms);
    let _ = writeln!(out, "    mean : {:.2} ms", r.latency.mean_ms);
    let _ = writeln!(out, "  scheduler lag p99: {:.2} ms", r.scheduler_lag_p99_ms);
    let _ = writeln!(
        out,
        "  bytes in         : {} ({:.1} KiB/s)",
        r.bytes_in,
        r.bytes_per_s / 1024.0
    );
    if let Some(ws) = &r.ws {
        let _ = writeln!(
            out,
            "  websocket        : held {} opened {} closed {} failed {}",
            r.ws_held, ws.opened, ws.closed, ws.failed
        );
        let _ = writeln!(
            out,
            "                     sent {} frames_rx {} bytes_rx {}",
            ws.sent, ws.frames_rx, ws.bytes_rx
        );
    }
    let _ = writeln!(out, "  fidelity         : {}", r.fidelity);
    let _ = writeln!(out, "  http             : {}", r.http_version);
    if let Some(p) = &r.proxy {
        let _ = writeln!(out, "  proxy            : {}", p);
    }
    let _ = writeln!(out, "  mutation         : {}", r.mutation_active);
    out
}

pub fn agg_to_latency(a: &Agg) -> LatencyBlock {
    let q = |p: f64| a.quantile(p).unwrap_or(0) as f64 / 1_000_000.0;
    LatencyBlock {
        p50_ms: q(0.50),
        p90_ms: q(0.90),
        p95_ms: q(0.95),
        p99_ms: q(0.99),
        mean_ms: a.mean().unwrap_or(0.0) / 1_000_000.0,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build(
    target: &str,
    strategy: &str,
    runtime: Duration,
    dispatched: u64,
    lat_lag: &(Agg, Agg),
    statuses: Vec<(u16, u64)>,
    errors: Vec<(crate::error::ErrorKind, u64)>,
    (bytes_in, bytes_out): (u64, u64),
    actual_rps: f64,
    target_rps: f64,
    ws: Option<WsStats>,
    ws_held: u64,
    fidelity: &str,
    http_version: &str,
    proxy: Option<String>,
    mutation: &str,
) -> RunReport {
    let total: f64 = statuses.iter().map(|c| c.1).sum::<u64>() as f64;
    RunReport {
        target: target.to_string(),
        strategy: strategy.to_string(),
        runtime_s: runtime.as_secs_f64(),
        requests_sent: dispatched,
        responses: statuses.iter().map(|c| c.1).sum::<u64>(),
        target_rps,
        actual_rps,
        statuses: statuses
            .into_iter()
            .map(|(code, count)| StatusLine {
                code,
                count,
                pct: if total > 0.0 {
                    (count as f64) * 100.0 / total
                } else {
                    0.0
                },
            })
            .collect(),
        errors: errors
            .into_iter()
            .map(|(kind, count)| ErrorLine {
                kind: kind.to_string(),
                count,
            })
            .collect(),
        latency: agg_to_latency(&lat_lag.0),
        scheduler_lag_p99_ms: lat_lag.1.quantile(0.99).unwrap_or(0) as f64 / 1_000_000.0,
        bytes_in,
        bytes_per_s: if runtime.as_secs_f64() > 0.0 {
            bytes_in as f64 / runtime.as_secs_f64()
        } else {
            0.0
        },
        bytes_out,
        ws,
        ws_held,
        coordinated_omission_corrected: true,
        fidelity: fidelity.to_string(),
        http_version: http_version.to_string(),
        proxy,
        mutation_active: mutation.to_string(),
    }
}
