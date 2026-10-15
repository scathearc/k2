//! Dynamic HTTP header and path mutation engine (nomore403-informed).
//!
//! Activates adaptively when the observed 403 ratio in the controller window
//! exceeds the configured threshold, escalating in stages:
//!   level 1 — rotate mitigation headers (X-Forwarded-For et al. with random IPs)
//!   level 2 — additionally mutate path structure (/%2e/, //, ; truncation)
//! De-escalates when 403 activity reaches zero and holds.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::MitigateCfg;

/// Shared, lock-free view of the currently active mutation level. `0` = off.
#[derive(Debug)]
pub struct MutationState {
    level: AtomicU64,
    header_cursor: AtomicU64,
    path_cursor: AtomicU64,
    always: bool,
}

pub const MITIGATION_HEADERS: &[&str] = &[
    "X-Forwarded-For",
    "X-Real-IP",
    "Client-IP",
    "X-Client-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Forwarded-Client-IP",
    "Fastly-Client-IP",
];

impl MutationState {
    pub fn new(cfg: MitigateCfg) -> Self {
        Self {
            level: AtomicU64::new(if cfg.always { 2 } else { 0 }),
            header_cursor: AtomicU64::new(0),
            path_cursor: AtomicU64::new(0),
            always: cfg.always,
        }
    }

    pub fn level(&self) -> u8 {
        self.level.load(Ordering::Relaxed).min(2) as u8
    }

    pub fn set_level(&self, l: u8) {
        let v = if self.always { 2 } else { u64::from(l.min(2)) };
        self.level.store(v, Ordering::Relaxed);
    }

    pub fn escalate(&self) {
        let l = self.level();
        if self.always {
            return;
        }
        self.level
            .store(u64::from((l + 1).min(2)), Ordering::Relaxed);
    }

    pub fn de_escalate(&self) {
        if self.always {
            return;
        }
        let l = self.level();
        if l > 0 {
            self.level.store(u64::from(l - 1), Ordering::Relaxed);
        }
    }

    /// Returns the mitigation header (name, random plausible client IP) for this request.
    pub fn mitigation_header(&self) -> (String, String) {
        let idx = self.header_cursor.fetch_add(1, Ordering::Relaxed);
        let name = MITIGATION_HEADERS[(idx as usize) % MITIGATION_HEADERS.len()];
        (name.to_string(), random_client_ip())
    }

    /// Applies deterministic-random path mutation when level >= 2.
    pub fn mutate_path(&self, raw_path_and_query: &str) -> String {
        if self.level() < 2 || raw_path_and_query.is_empty() {
            return raw_path_and_query.to_string();
        }
        let idx = self.path_cursor.fetch_add(1, Ordering::Relaxed);
        // split path from any query/fragment tail
        let sep = raw_path_and_query
            .find(['?', '#'])
            .unwrap_or(raw_path_and_query.len());
        let path = &raw_path_and_query[..sep];
        let tail = &raw_path_and_query[sep..];
        if path.is_empty() {
            return raw_path_and_query.to_string();
        }
        let variant = match idx % 4 {
            0 => format!("/%2e{path}"),                         // dot-segment prefix
            1 => format!("//{}", path.trim_start_matches('/')), // double slash
            2 => {
                let mut p = path.splitn(2, '/');
                let first = p.next().unwrap_or("");
                let rest = p.next().unwrap_or("");
                format!(
                    "/{first};jsessionid=x{}/{rest}",
                    if rest.is_empty() { "" } else { "/" }
                )
            }
            _ => format!("{path}/%2e"), // trailing dot segment
        };
        format!("{variant}{tail}")
    }

    /// The currently rendered mutation level label for telemetry display.
    pub fn level_label(&self) -> &'static str {
        match self.level() {
            0 => "none",
            1 => "headers",
            _ => "headers+path",
        }
    }
}

fn random_client_ip() -> String {
    // CGNAT 100.64/10 plausible upstream adder.
    let b = rand::random_range(64u8..=127);
    let c = rand::random_range(0u8..=255);
    let d = rand::random_range(2u8..=254);
    format!("100.{b}.{c}.{d}")
}

/// Controller helper: reacts to the observed 403 window ratio.
pub fn react(state: &Arc<MutationState>, cfg: MitigateCfg, ratio403: f64) {
    if !cfg.enabled {
        if !cfg.always {
            state.set_level(0);
        }
        return;
    }
    if cfg.always {
        state.set_level(2);
        return;
    }
    if ratio403 > cfg.threshold {
        state.escalate();
    } else if ratio403 == 0.0 {
        state.de_escalate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(always: bool) -> MitigateCfg {
        MitigateCfg {
            enabled: true,
            always,
            threshold: 0.05,
        }
    }

    #[test]
    fn escalation_chain() {
        let m = MutationState::new(cfg(false));
        assert_eq!(m.level(), 0);
        m.escalate();
        assert_eq!(m.level(), 1);
        m.escalate();
        assert_eq!(m.level(), 2);
        m.escalate();
        assert_eq!(m.level(), 2); // clamped
        m.de_escalate();
        assert_eq!(m.level(), 1);
        m.de_escalate();
        assert_eq!(m.level(), 0);
    }

    #[test]
    fn always_mode_pins_level_two() {
        let m = MutationState::new(cfg(true));
        assert_eq!(m.level(), 2);
        m.escalate();
        assert_eq!(m.level(), 2);
        m.de_escalate();
        assert_eq!(m.level(), 2);
    }

    #[test]
    fn mitigation_headers_rotate() {
        let m = MutationState::new(cfg(true));
        let mut seen = std::collections::HashSet::new();
        for _ in 0..MITIGATION_HEADERS.len() {
            seen.insert(m.mitigation_header().0);
        }
        assert_eq!(seen.len(), MITIGATION_HEADERS.len());
    }

    #[test]
    fn path_variants_stay_well_formed() {
        let m = MutationState::new(cfg(true));
        for _ in 0..8 {
            let p = m.mutate_path("/api/v1/thing?query=1");
            assert!(p.starts_with('/'), "path {p}");
            assert!(p.ends_with("query=1"), "path {p}");
        }
        // no query tail also fine
        let p = m.mutate_path("/api/v1/thing");
        assert!(p.starts_with('/'));
    }

    #[test]
    fn react_gates() {
        let m = Arc::new(MutationState::new(cfg(false)));
        react(&m, cfg(false), 0.5);
        assert!(m.level() >= 1);
        react(&m, cfg(false), 0.0);
        // de-escalates over time as calls repeat
        m.de_escalate();
        m.de_escalate();
        assert_eq!(m.level(), 0);
    }
}
