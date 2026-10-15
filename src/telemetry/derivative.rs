//! Latency derivative (dLat/dt) detection over a sliding 100ms-tick window.

use std::collections::VecDeque;

/// Detects the rate of change of a tracked percentile.
///
/// `slope()` compares the newest sample against the minimum observed inside
/// the retained window (noise-robust "have we been climbing?" detector). Both
/// absolute (ns/s) and relative (per-second fraction of current p99) values
/// are exposed.
#[derive(Debug)]
pub struct Deriv {
    samples: VecDeque<(u64 /* ms */, f64 /* p99 ns */)>,
    max_len: usize,
}

impl Deriv {
    pub fn new(max_window_ticks: usize) -> Self {
        Self {
            samples: VecDeque::new(),
            max_len: max_window_ticks.max(2),
        }
    }

    pub fn push(&mut self, tick_ms: u64, value: f64) {
        self.samples.push_back((tick_ms, value));
        while self.samples.len() > self.max_len {
            self.samples.pop_front();
        }
    }

    pub fn slope(&self) -> f64 {
        let (Some(&(t_last, v_last)), Some(&(t_min, v_min))) =
            (self.samples.back(), self.min_sample())
        else {
            return 0.0;
        };
        let dt_s = t_last.saturating_sub(t_min) as f64 / 1000.0;
        if dt_s <= 0.0 {
            return 0.0;
        }
        ((v_last - v_min) / dt_s).max(0.0)
    }

    fn min_sample(&self) -> Option<&(u64, f64)> {
        self.samples.iter().min_by(|a, b| a.1.total_cmp(&b.1))
    }

    pub fn relative(&self) -> f64 {
        let last = self.samples.back().map(|(_, v)| *v).unwrap_or(0.0);
        if last <= 0.0 {
            return 0.0;
        }
        self.slope() / last
    }

    /// Degrading verdict: derivative breach or observed transport/status errors.
    pub fn is_degrading(&self, rel_delta: f64, err_rate: f64) -> bool {
        if err_rate > 0.0 {
            return true;
        }
        let last = self.samples.back().map(|(_, v)| *v).unwrap_or(0.0);
        if last <= 0.0 {
            return false; // no signal yet
        }
        self.relative() >= rel_delta
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_series_is_stable() {
        let mut d = Deriv::new(5);
        for i in 0..10 {
            d.push(i * 100, 5_000_000.0);
        }
        assert!(d.slope() == 0.0);
        assert!(!d.is_degrading(0.35, 0.0));
    }

    #[test]
    fn climbing_series_degrades() {
        let mut d = Deriv::new(5);
        // 5ms -> 9ms over 400ms => 10us/ms => 10ms/s relative vs 9ms => >>1.0
        for (i, v) in [
            (0u64, 5.0e6),
            (100, 6.0e6),
            (200, 7.0e6),
            (300, 8.0e6),
            (400, 9.0e6),
        ] {
            d.push(i, v);
        }
        assert!(d.relative() > 0.35, "rel {}", d.relative());
        assert!(d.is_degrading(0.35, 0.0));
    }

    #[test]
    fn errors_force_degrading() {
        let mut d = Deriv::new(5);
        d.push(0, 1.0e6);
        d.push(100, 1.0e6);
        assert!(d.is_degrading(0.35, 0.01));
    }

    #[test]
    fn no_signal_is_stable() {
        let mut d = Deriv::new(5);
        d.push(0, 0.0);
        d.push(100, 0.0);
        assert!(!d.is_degrading(0.35, 0.0));
    }
}
