//! AIMD saturation tracking: additive increase / multiplicative decrease.

use std::time::Duration;

use crate::config::AimdCfg;
use crate::telemetry::derivative::Deriv;

/// Parameters for the Knee-of-Curve AIMD controller.
#[derive(Debug, Clone, Copy)]
pub struct AimdParams {
    pub alpha: f64,
    pub beta: f64,
    pub delta: f64,
    pub min_rate: f64,
    pub max_rate: f64,
}

impl AimdParams {
    pub fn from_cfg(cfg: &AimdCfg) -> Self {
        Self {
            alpha: cfg.alpha,
            beta: cfg.beta,
            delta: cfg.delta,
            min_rate: cfg.min_rate,
            max_rate: cfg.max_rate,
        }
    }
}

/// Knee-hunter state.
#[derive(Debug)]
pub struct Aimd {
    pub p: AimdParams,
    pub rate: f64,
    /// Max rate observed while the target was still stable — the knee estimate.
    pub peak: f64,
    deriv: Deriv,
}

impl Aimd {
    pub fn new(p: AimdParams, initial: f64) -> Self {
        Self {
            rate: initial.max(p.min_rate).min(p.max_rate),
            peak: initial.max(p.min_rate),
            p,
            deriv: Deriv::new(6),
        }
    }

    /// One 100ms controller tick. `tick_ms` is campaign elapsed ms,
    /// `window_p99_ns` the drained window p99 (0 when the window had no
    /// samples), `err_rate` the window error ratio.
    pub fn tick(&mut self, tick_ms: u64, window_p99_ns: f64, err_rate: f64) -> f64 {
        let has_signal = window_p99_ns > 0.0;
        if !has_signal {
            // empty window (low absolute rates): hold, judge nothing
            return self.rate;
        }
        self.deriv.push(tick_ms, window_p99_ns);
        let rel = self.deriv.relative();
        let degrading = rel >= self.p.delta || err_rate > 0.0;
        if degrading {
            self.rate = (self.rate * self.p.beta).max(self.p.min_rate);
        } else {
            self.rate = (self.rate + self.p.alpha).min(self.p.max_rate);
            self.peak = self.peak.max(self.rate);
        }
        let _ = Duration::ZERO;
        self.rate
    }

    pub fn label(&self) -> String {
        format!(
            "Knee-of-Curve AIMD (rate {:.0}, peak {:.0})",
            self.rate, self.peak
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> AimdParams {
        AimdParams {
            alpha: 100.0,
            beta: 0.75,
            delta: 0.35,
            min_rate: 10.0,
            max_rate: 100_000.0,
        }
    }

    #[test]
    fn increases_when_stable() {
        let mut a = Aimd::new(set(), 100.0);
        for i in 0..3u64 {
            a.tick(i * 100, 1.0e6, 0.0);
        }
        assert!((a.rate - 400.0).abs() < 1e-6, "rate {}", a.rate);
        assert_eq!(a.peak, a.rate);
    }

    #[test]
    fn decreases_on_derivative_breach() {
        let mut a = Aimd::new(set(), 1000.0);
        a.tick(0, 1.0e6, 0.0); // stable -> 1100
        a.tick(100, 2.0e6, 0.0); // +1ms over 100ms => 10ms/s rel 5.0 >= delta -> 825
        assert!((a.rate - 825.0).abs() < 1e-6, "rate {}", a.rate);
    }

    #[test]
    fn decreases_on_errors() {
        let mut a = Aimd::new(set(), 1000.0);
        a.tick(0, 1.0e6, 0.0); // stable -> 1100
        a.tick(100, 1.02e6, 0.02);
        assert!((a.rate - 825.0).abs() < 1e-6, "rate {}", a.rate);
    }

    #[test]
    fn floors_and_ceilings_hold() {
        let mut a = Aimd::new(set(), 10.0);
        a.tick(0, 1.0e6, 0.0); // stable -> 110
        a.tick(100, 1.0e6, 0.9); // errors -> 82.5
        assert!((a.rate - 82.5).abs() < 1e-6, "rate {}", a.rate);
        a.rate = 99_999.0;
        a.tick(200, 1.0e6, 0.0);
        assert_eq!(a.rate, 100_000.0);
    }

    #[test]
    fn idle_window_holds() {
        let mut a = Aimd::new(set(), 100.0);
        a.tick(0, 0.0, 0.0);
        assert_eq!(a.rate, 100.0);
    }
}
