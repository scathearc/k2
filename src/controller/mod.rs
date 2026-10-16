//! Policy & strategy control: closed-loop controller interface module.

pub mod aimd;
pub mod mutation;
pub mod pid;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc;

use crate::config::{Config, PulseCfg, StrategyKind};
use crate::telemetry::error_classifier::WindowTotals;
use aimd::Aimd;
use pid::Pid;

/// Controller commands from TUI / Web / tests.
#[derive(Debug, Clone)]
pub enum ControlMsg {
    SetStrategy(StrategyKind),
    AdjustRate(f64),
    SetRate(f64),
    ToggleEntropy,
    /// Graceful drain: stop scheduling, finish in-flight, write report.
    Quit,
}

/// Encapsulates every closed-loop adjustment: AIMD knee-hunting, pulse
/// modulation, brownout pinning, manual control with smooth rate limiting.
pub struct Controller {
    strategy: StrategyKind,
    rate: f64,
    knee: Aimd,
    pulse: PulseCfg,
    brownout_pct: f64,
    manual_rate: f64,
    base_fixed_rate: f64,
    pub mutation: Arc<crate::controller::mutation::MutationState>,
    pid: Pid,
    msg_rx: mpsc::UnboundedReceiver<ControlMsg>,
    entropy: Arc<AtomicBool>,
    max_step_pct: f64,
    min_rate: f64,
    max_rate: f64,
    mitigate_cfg: crate::config::MitigateCfg,
    quit_flag: bool,
}

impl Controller {
    pub fn new(
        cfg: &Config,
        msg_rx: mpsc::UnboundedReceiver<ControlMsg>,
        entropy: Arc<AtomicBool>,
        mutation: Arc<crate::controller::mutation::MutationState>,
    ) -> Self {
        let start = cfg
            .rate
            .unwrap_or(8.0)
            .min(cfg.aimd.max_rate)
            .max(cfg.aimd.min_rate);
        Self {
            strategy: cfg.strategy,
            rate: start,
            knee: Aimd::new(aimd::AimdParams::from_cfg(&cfg.aimd), start),
            pulse: cfg.pulse,
            brownout_pct: cfg.brownout_pct,
            manual_rate: start * 2.0,
            base_fixed_rate: cfg.rate.unwrap_or(0.0),
            mutation,
            // saturation guard: proportional pull on realized vs commanded
            pid: Pid::new(4.0, 2.0, 0.0, -cfg.rate.unwrap_or(1.0).max(1.0) * 0.25, 0.0),
            msg_rx,
            entropy,
            max_step_pct: 0.25,
            min_rate: cfg.aimd.min_rate,
            max_rate: cfg.aimd.max_rate.max(cfg.rate.unwrap_or(0.0)),
            mitigate_cfg: cfg.mitigate,
            quit_flag: false,
        }
    }

    /// One-shot graceful-drain request flag (set by TUI/Web Quit).
    pub fn poll_quit(&mut self) -> bool {
        std::mem::take(&mut self.quit_flag)
    }

    /// Non-blocking drain of queued control messages.
    fn apply_msgs(&mut self) {
        while let Ok(m) = self.msg_rx.try_recv() {
            match m {
                ControlMsg::SetStrategy(s) => {
                    if s != self.strategy {
                        self.strategy = s;
                        if s == StrategyKind::Manual {
                            self.manual_rate = self.rate * 2.0;
                        } else if s == StrategyKind::Brownout {
                            self.inherit_brownout();
                        }
                    }
                }
                ControlMsg::AdjustRate(d) => {
                    self.manual_rate = (self.manual_rate + d).max(self.min_rate).min(self.max_rate);
                    if self.strategy == StrategyKind::Manual {
                        self.rate = self.manual_rate;
                    }
                }
                ControlMsg::SetRate(r) => {
                    self.manual_rate = r.max(self.min_rate).min(self.max_rate);
                    if self.strategy == StrategyKind::Manual {
                        self.rate = self.manual_rate;
                    }
                }
                ControlMsg::ToggleEntropy => {
                    let cur = self.entropy.load(Ordering::Relaxed);
                    self.entropy.store(!cur, Ordering::Relaxed);
                }
                ControlMsg::Quit => {
                    self.quit_flag = true;
                }
            }
        }
    }

    fn inherit_brownout(&mut self) {
        self.manual_rate = (self.knee.peak * self.brownout_pct).max(self.min_rate);
    }

    fn clamp_rate(&self, r: f64) -> f64 {
        r.clamp(self.min_rate, self.max_rate)
    }

    /// One 100ms controller tick. Returns the commanded target rate.
    /// `status_ratio` is the window non-2xx + transport-error ratio (the
    /// status-first degradation signal).
    pub fn on_tick(
        &mut self,
        tick_ms: u64,
        window: &WindowTotals,
        window_p99_ns: f64,
        status_ratio: f64,
        actual_rps: f64,
    ) -> f64 {
        self.apply_msgs();

        let attempts = window.count + window.errors;
        let err_rate = if attempts > 0 {
            window.errors as f64 / attempts as f64
        } else {
            0.0
        };

        // 403-reactive mutation engine
        let ratio403 = if attempts > 0 {
            window.s403 as f64 / attempts as f64
        } else {
            0.0
        };
        mutation::react(&self.mutation, self.mitigate_cfg, ratio403);

        let next = match self.strategy {
            StrategyKind::Fixed => {
                // PID guards worker starvation: downward correction only.
                let corr = self.pid.step(self.base_fixed_rate, actual_rps, 0.1);
                self.clamp_rate(self.base_fixed_rate + corr)
            }
            StrategyKind::Knee => {
                let r = self
                    .knee
                    .tick(tick_ms, window_p99_ns, err_rate, status_ratio);
                self.clamp_rate(r)
            }
            StrategyKind::Pulse => {
                let t = tick_ms as f64 / 1000.0;
                let phase = t % self.pulse.period;
                let hi_dur = self.pulse.period * self.pulse.duty;
                let base = if phase < hi_dur {
                    self.pulse.hi
                } else {
                    self.pulse.lo
                };
                self.clamp_rate(base)
            }
            StrategyKind::Brownout => self.clamp_rate(self.knee.peak * self.brownout_pct),
            StrategyKind::Manual => self.clamp_rate(self.manual_rate),
        };

        // Smooth transitions: clamp step change per tick.
        let max_jump = (self.rate * self.max_step_pct).max(1.0);
        let delta = (next - self.rate).clamp(-max_jump, max_jump);
        self.rate = self.clamp_rate(self.rate + delta);
        self.rate
    }

    pub fn strategy(&self) -> StrategyKind {
        self.strategy
    }

    pub fn label(&self) -> String {
        match self.strategy {
            StrategyKind::Fixed => format!("Fixed {:.0} rps", self.base_fixed_rate),
            StrategyKind::Knee => self.knee.label(),
            StrategyKind::Pulse => format!(
                "Square-Wave Pulse {:.0}/{:.0} (p {:.1}s d {:.0}%)",
                self.pulse.hi,
                self.pulse.lo,
                self.pulse.period,
                self.pulse.duty * 100.0
            ),
            StrategyKind::Brownout => format!("Brownout {:.0}%", self.brownout_pct * 100.0),
            StrategyKind::Manual => format!("Manual {:.0} rps", self.manual_rate),
        }
    }
}
