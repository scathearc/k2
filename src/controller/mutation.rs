//! Dynamic HTTP header/path/method mutation engine (nomore403-informed).
//!
//! Three tool families escalate as an adaptive ladder when the observed 403
//! ratio in the controller window exceeds the threshold:
//!   level 1 — rotate mitigation headers (X-Forwarded-For et al. with random
//!             CGNAT-source client IPs)
//!   level 2 — additionally mutate path structure (/%2e/, //, ; truncation)
//!   level 3 — additionally attach method-override headers
//!             (X-HTTP-Method-Override / X-HTTP-Method / X-Method-Override ×
//!             DELETE / PATCH / PUT)
//!
//! **Discovery is sticky.** Escalation reacts to 403 spikes, but a level that
//! produced clean traffic is held (with per-tool 403-rate EMA so the working
//! variants are preferred and failing variants are skipped) — a proven
//! mitigation becomes the campaign default instead of re-paying a 403 per
//! request per cycle. Demotion only happens after ~3s of strictly-zero 403
//! activity, one level at a time.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::config::MitigateCfg;

/// IP-forwarding header family (client-source spoofing).
pub const IP_TOOLS: &[&str] = &[
    "X-Forwarded-For",
    "X-Real-IP",
    "Client-IP",
    "X-Client-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Forwarded-Client-IP",
    "Fastly-Client-IP",
];

/// Method-override family: (header, method-value) combinations. Mirrors the
/// nomore403 probe set — WAF rules that block a literal method/path often
/// pass the request when the semantic method arrives via header.
pub const METHOD_OVERRIDE_COMBOS: &[(&str, &str)] = &[
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-HTTP-Method-Override", "PATCH"),
    ("X-HTTP-Method-Override", "PUT"),
    ("X-HTTP-Method", "DELETE"),
    ("X-HTTP-Method", "PATCH"),
    ("X-HTTP-Method", "PUT"),
    ("X-Method-Override", "DELETE"),
    ("X-Method-Override", "PATCH"),
    ("X-Method-Override", "PUT"),
];

const N_IP: usize = IP_TOOLS.len();
const N_MO: usize = METHOD_OVERRIDE_COMBOS.len();
pub const TOTAL_TOOLS: usize = N_IP + N_MO;

/// Per-tool recent-403-rate EMA; low = this variant tends to succeed.
#[derive(Debug, Default)]
struct ToolStat {
    ema: Vec<f64>,
}

impl ToolStat {
    fn new() -> Self {
        Self {
            ema: vec![0.0; TOTAL_TOOLS],
        }
    }
}

/// One applied mitigation tag, carried on the executed request so its outcome
/// can feed back into tool selection.
pub type MitigationTag = (String, String);

/// Shared, lock-free state of the mutation engine.
#[derive(Debug)]
pub struct MutationState {
    level: AtomicU64,
    max_level: u8,
    header_cursor: AtomicU64,
    path_cursor: AtomicU64,
    tools: Mutex<ToolStat>,
    clean_windows: AtomicU64,
    always: bool,
}

/// Consecutive fully-clean (403-ratio 0) ticks required before demotion.
pub const DEMOTE_AFTER_TICKS: u64 = 30;

impl MutationState {
    pub fn new(cfg: MitigateCfg) -> Self {
        let max_level = if cfg.method_override { 3u8 } else { 2u8 };
        Self {
            level: AtomicU64::new(if cfg.always { u64::from(max_level) } else { 0 }),
            max_level,
            header_cursor: AtomicU64::new(0),
            path_cursor: AtomicU64::new(0),
            tools: Mutex::new(ToolStat::new()),
            clean_windows: AtomicU64::new(0),
            always: cfg.always,
        }
    }

    pub fn level(&self) -> u8 {
        self.level
            .load(Ordering::Relaxed)
            .min(u64::from(self.max_level)) as u8
    }

    pub fn max_level(&self) -> u8 {
        self.max_level
    }

    pub fn set_level(&self, l: u8) {
        if self.always {
            return;
        }
        self.level
            .store(u64::from(l.min(self.max_level)), Ordering::Relaxed);
        if l == 0 {
            self.clean_windows.store(0, Ordering::Relaxed);
        }
    }

    pub fn escalate(&self) {
        if self.always {
            return;
        }
        let l = self.level();
        if l < self.max_level {
            self.level.store(u64::from(l + 1), Ordering::Relaxed);
        }
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

    /// One 100ms controller tick of the sticky escalation hysteresis.
    pub fn tick_mitigation(&self, ratio403: f64, threshold: f64) {
        if self.always {
            return;
        }
        if !threshold.is_finite() {
            return;
        }
        if ratio403 > threshold {
            // Blocked again: forget cleanliness, escalate the ladder.
            self.clean_windows.store(0, Ordering::Relaxed);
            self.escalate();
        } else {
            // Sub-threshold ratios: hold the level. Any nonzero 403 residue
            // means one rotation variant is failing — tool EMA feedback steers
            // selection away from it; strictly-zero windows build the clean
            // streak that eventually (slowly) demotes a proven level.
            if self.level() > 0 && ratio403 == 0.0 {
                let n = self.clean_windows.fetch_add(1, Ordering::Relaxed) + 1;
                if n >= DEMOTE_AFTER_TICKS {
                    self.de_escalate();
                    self.clean_windows.store(0, Ordering::Relaxed);
                }
            }
        }
    }

    /// Deterministic tool pick: 1-in-10 uniform exploration, otherwise the
    /// variant with the lowest recent 403 rate within the family.
    fn pick_tool(&self, family: ToolFamily) -> usize {
        let cursor = self.header_cursor.fetch_add(1, Ordering::Relaxed);
        let (start, len) = match family {
            ToolFamily::IpHeader => (0usize, N_IP),
            ToolFamily::MethodOverride => (N_IP, N_MO),
        };
        if cursor.is_multiple_of(10) {
            return start + (mix(cursor) % len as u64) as usize;
        }
        let tools = self.tools.lock().unwrap();
        (start..start + len)
            .min_by(|a, b| tools.ema[*a].total_cmp(&tools.ema[*b]))
            .expect("non-empty family")
    }

    /// Current IP-forwarding tool header (name, random client IP).
    pub fn mitigation_header(&self) -> MitigationTag {
        let idx = self.pick_tool(ToolFamily::IpHeader);
        (IP_TOOLS[idx].to_string(), random_client_ip())
    }

    /// Current method-override tool header (name, method value).
    pub fn method_override_header(&self) -> MitigationTag {
        let idx = self.pick_tool(ToolFamily::MethodOverride) - N_IP;
        let (name, value) = METHOD_OVERRIDE_COMBOS[idx];
        (name.to_string(), value.to_string())
    }

    /// Feed the result of one mitigated request back into tool ranking.
    /// `is_403` marks a blocked response; anything else counts as success.
    pub fn report_result(&self, tags: &[MitigationTag], is_403: bool) {
        if tags.is_empty() {
            return;
        }
        let mut tools = self.tools.lock().unwrap();
        let bump = if is_403 { ALPHA } else { 0.0 };
        for (name, _) in tags {
            if let Some(i) = IP_TOOLS.iter().position(|n| *n == name) {
                tools.ema[i] = tools.ema[i] * (1.0 - ALPHA) + bump;
            } else if let Some(k) = METHOD_OVERRIDE_COMBOS.iter().position(|(n, _)| *n == name) {
                let idx = N_IP + k;
                tools.ema[idx] = tools.ema[idx] * (1.0 - ALPHA) + bump;
            }
        }
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
                format!("/{first};jsessionid=x/{rest}")
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
            2 => "headers+path",
            _ => "headers+path+method",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ToolFamily {
    IpHeader,
    MethodOverride,
}

const ALPHA: f64 = 0.3;

#[inline]
fn mix(seq: u64) -> u64 {
    seq.wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407)
        .rotate_right(17)
}

fn random_client_ip() -> String {
    // CGNAT 100.64/10 plausible upstream adder.
    let b = rand::random_range(64u8..=127);
    let c = rand::random_range(0u8..=255);
    let d = rand::random_range(2u8..=254);
    format!("100.{b}.{c}.{d}")
}

/// Controller helper: sticky 403-reactive policy (hysteresis lives inside the
/// state so the working level becomes the de-facto default).
pub fn react(state: &Arc<MutationState>, cfg: MitigateCfg, ratio403: f64) {
    if !cfg.enabled {
        if !cfg.always {
            state.set_level(0);
        }
        return;
    }
    state.tick_mitigation(ratio403, cfg.threshold);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(always: bool) -> MitigateCfg {
        MitigateCfg {
            enabled: true,
            always,
            threshold: 0.05,
            method_override: false,
        }
    }

    fn cfg_mo(always: bool) -> MitigateCfg {
        MitigateCfg {
            enabled: true,
            always,
            threshold: 0.05,
            method_override: true,
        }
    }

    #[test]
    fn escalation_chain_caps_at_two_without_method_override() {
        let m = MutationState::new(cfg(false));
        assert_eq!(m.level(), 0);
        m.escalate();
        assert_eq!(m.level(), 1);
        m.escalate();
        assert_eq!(m.level(), 2);
        m.escalate();
        assert_eq!(m.level(), 2); // capped
        m.de_escalate();
        assert_eq!(m.level(), 1);
        m.de_escalate();
        assert_eq!(m.level(), 0);
    }

    #[test]
    fn escalation_reaches_method_overrides() {
        let m = MutationState::new(cfg_mo(false));
        m.escalate();
        m.escalate();
        m.escalate();
        assert_eq!(m.level(), 3);
        let (name, value) = m.method_override_header();
        assert!(
            name == "X-HTTP-Method-Override"
                || name == "X-HTTP-Method"
                || name == "X-Method-Override",
            "got {name}"
        );
        assert!(
            matches!(value.as_str(), "DELETE" | "PATCH" | "PUT"),
            "got {value}"
        );
    }

    #[test]
    fn always_mode_pins_highest_level() {
        let m = MutationState::new(cfg_mo(true));
        assert_eq!(m.level(), 3);
        m.escalate();
        assert_eq!(m.level(), 3);
        m.de_escalate();
        assert_eq!(m.level(), 3);
    }

    #[test]
    fn sticky_level_survives_clean_windows() {
        let m = MutationState::new(cfg(false));
        m.escalate(); // level 1 active
        // Storm passes; mitigation works: many clean ticks
        for _ in 0..(DEMOTE_AFTER_TICKS - 1) {
            m.tick_mitigation(0.0, 0.05);
        }
        assert_eq!(m.level(), 1, "working level must be held");
        // Only after the full clean streak does it hand control back.
        m.tick_mitigation(0.0, 0.05);
        assert_eq!(m.level(), 0, "slow decay after sustained cleanliness");
    }

    #[test]
    fn low_nonzero_403_ratio_holds_without_escalating() {
        let m = MutationState::new(cfg(false));
        m.escalate();
        m.escalate();
        assert_eq!(m.level(), 2);
        for _ in 0..10 {
            m.tick_mitigation(0.01, 0.05); // under threshold: hold
        }
        assert_eq!(m.level(), 2);
    }

    #[test]
    fn spike_resets_clean_streak_and_escalates() {
        let m = MutationState::new(cfg(false));
        m.escalate();
        for _ in 0..(DEMOTE_AFTER_TICKS - 2) {
            m.tick_mitigation(0.0, 0.05);
        }
        m.tick_mitigation(0.5, 0.05); // blocked again
        assert_eq!(m.level(), 2);
        for _ in 0..(DEMOTE_AFTER_TICKS - 2) {
            m.tick_mitigation(0.0, 0.05);
        }
        assert_eq!(m.level(), 2, "streak reset by the spike");
    }

    #[test]
    fn failing_tools_rank_down() {
        let m = MutationState::new(cfg(false));
        // Feed: header at index 0 fails 10x; another succeeds repeatedly.
        for _ in 0..10 {
            m.report_result(&[(IP_TOOLS[0].to_string(), "1.2.3.4".into())], true);
        }
        for _ in 0..3 {
            m.report_result(&[(IP_TOOLS[3].to_string(), "1.2.3.4".into())], false);
        }
        // Many picks: the failing tool must only surface via the 1-in-10
        // exploration channel, never as the ranked default.
        let mut hit_failing = 0;
        for _i in 0..100u64 {
            let (name, _) = m.mitigation_header();
            if name == IP_TOOLS[0] {
                hit_failing += 1;
            }
        }
        assert!(
            hit_failing <= 20,
            "failing tool picked {hit_failing}/100 — EMA ranking not steering away"
        );
    }

    #[test]
    fn mitigation_headers_rotate_diversely() {
        let m = MutationState::new(cfg(true));
        let mut seen = std::collections::HashSet::new();
        for _ in 0..N_IP * 4 {
            seen.insert(m.mitigation_header().0);
        }
        // exploration keeps most names live over time
        assert!(seen.len() >= 3, "saw {seen:?}");
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
        // sticky: stays up during the clean streak
        assert_eq!(m.level(), 1);
    }
}
