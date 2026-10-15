//! Intent scheduler: leaks a bucket at the commanded target rate, decoupled
//! from worker execution. Every intent carries its intended dispatch instant —
//! the anchor that keeps latency accounting immune to coordinated omission.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};

use crate::config::{Config, WsMode};
use crate::engine::request::Materializer;
use crate::engine::{Intent, Work};
use crate::telemetry::Telemetry;

pub struct Scheduler {
    pub cfg: Arc<Config>,
    pub materializer: Arc<Materializer>,
    pub intents_tx: mpsc::Sender<Intent>,
    pub rate_rx: watch::Receiver<f64>,
    pub telemetry: Arc<Telemetry>,
    pub stop_rx: watch::Receiver<bool>,
}

impl Scheduler {
    /// Drive the campaign until duration/request cap/stop.
    pub async fn run(self) {
        let Self {
            cfg,
            materializer,
            intents_tx,
            rate_rx,
            telemetry,
            mut stop_rx,
        } = self;
        let start = Instant::now();
        let cap = cfg.requests;
        let duration = cfg.duration;
        let ws = cfg.ws.clone();
        let poisson = cfg.poisson;

        let mut seq: u64 = 0;
        let mut next_arrival: Instant = start;

        loop {
            if *stop_rx.borrow() {
                break;
            }
            if let Some(n) = cap
                && seq >= n
            {
                break;
            }
            if let Some(d) = duration
                && start.elapsed() >= d
            {
                break;
            }

            let rate = {
                let r = *rate_rx.borrow();
                if r <= 0.01 { 0.01 } else { r }
            };
            let dt = 1.0 / rate;

            // Slip guard: never build an unbounded backlog of late slots.
            let now = Instant::now();
            if now > next_arrival + Duration::from_secs_f64(dt) + Duration::from_millis(50) {
                next_arrival = now;
            }

            loop {
                if *stop_rx.borrow() {
                    break;
                }
                if let Some(n) = cap
                    && seq >= n
                {
                    break;
                }
                if let Some(d) = duration
                    && start.elapsed() >= d
                {
                    break;
                }

                let work = match &ws {
                    Some(mode) => ws_pick(telemetry.ws_held(), mode, seq),
                    None => Work::HttpReq,
                };

                let spec = materializer.materialize(seq);
                let intent = Intent {
                    seq,
                    intended_send: next_arrival,
                    spec,
                    work,
                };
                seq += 1;
                telemetry.dispatched_inc();

                // Bounded-channel backpressure: late dispatches carry honest
                // intended_send stamps rather than being dropped.
                if intents_tx.send(intent).await.is_err() {
                    return; // workers gone
                }

                // Advance the arrival accumulator (poisson: independent Exp sample).
                next_arrival = if poisson {
                    let x = rand::random::<f64>().max(1e-9);
                    next_arrival + Duration::from_secs_f64(-x.ln() / rate)
                } else {
                    next_arrival + Duration::from_secs_f64(dt)
                };

                // Micro-batch only while further slots are already due.
                if next_arrival > Instant::now() {
                    break;
                }
                if seq.checked_rem(4096) == Some(0) {
                    break;
                }
            }

            tokio::select! {
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(next_arrival)) => {}
                _ = wait_stop(&mut stop_rx) => {}
            }
        }
        // Dropping `intents_tx` closes the channel: workers drain, then exit.
    }
}

async fn wait_stop(stop_rx: &mut watch::Receiver<bool>) {
    if *stop_rx.borrow() {
        return;
    }
    let _ = stop_rx.changed().await;
}

fn ws_pick(held: u64, mode: &WsMode, seq: u64) -> Work {
    if held < mode.hold {
        return Work::WsOpen;
    }
    if mode.churn_per_s <= 0.0 && mode.send_per_s <= 0.0 {
        return Work::WsSend;
    }
    let close = (mode.churn_per_s.max(0.0) * 1000.0) as u64;
    let send = (mode.send_per_s.max(0.0) * 1000.0) as u64;
    let total = (close + send).max(1);
    let pick = mix_seq(seq) % total;
    if pick < send && send > 0 {
        Work::WsSend
    } else if held > 0 {
        Work::WsClose
    } else {
        Work::WsOpen
    }
}

#[inline]
fn mix_seq(seq: u64) -> u64 {
    seq.wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(hold: u64, churn: f64, send: f64) -> WsMode {
        WsMode {
            hold,
            churn_per_s: churn,
            send_per_s: send,
            size: 64,
        }
    }

    #[test]
    fn ws_open_until_hold_reached() {
        for seq in 0..50u64 {
            assert_eq!(ws_pick(0, &mode(100, 10.0, 50.0), seq), Work::WsOpen);
        }
    }

    #[test]
    fn ws_mix_after_hold() {
        let m = mode(10, 10.0, 50.0);
        let mut sends = 0;
        let mut closes = 0;
        for seq in 0..4000u64 {
            match ws_pick(10, &m, seq) {
                Work::WsSend => sends += 1,
                Work::WsClose => closes += 1,
                Work::WsOpen => unreachable!(),
                Work::HttpReq => unreachable!(),
            }
        }
        assert!(sends > 1000, "sends {sends}");
        assert!(closes > 100, "closes {closes}");
        assert!(sends > closes);
    }

    #[test]
    fn hold_reached_means_no_open() {
        let m = mode(1, 10.0, 0.0);
        for seq in 0..100u64 {
            assert_ne!(ws_pick(1, &m, seq), Work::WsOpen);
        }
    }
}
