//! Tokio worker pool dispatcher: pulls intents, runs the right engine,
//! feeds telemetry (including mitigation tool outcome feedback).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use crate::config::{Config, HttpVersion};
use crate::controller::mutation::MutationState;
use crate::engine::client::WreqPool;
use crate::engine::h3::H3Engine;
use crate::engine::ws::WsEngine;
use crate::engine::{Intent, Work};
use crate::telemetry::Telemetry;

/// The worker-facing engine cell: owns the selected protocol paths.
pub struct Engine {
    http: Arc<WreqPool>,
    h3: Option<Arc<H3Engine>>,
    ws: Option<Arc<WsEngine>>,
    http_version: HttpVersion,
    ws_mode: Option<crate::config::WsMode>,
    concurrency: usize,
    mutation: Option<Arc<MutationState>>,
}

impl Engine {
    pub async fn build(
        cfg: &Config,
        shutdown_rx: watch::Receiver<bool>,
        mutation: Option<Arc<MutationState>>,
    ) -> crate::error::K2Result<Self> {
        let http = WreqPool::build(cfg)?;
        let h3 = match cfg.http_version {
            HttpVersion::H3 => Some(H3Engine::build(cfg).await?),
            _ => None,
        };
        let ws = match (&cfg.ws, cfg.http_version) {
            (Some(mode), HttpVersion::Auto | HttpVersion::H1 | HttpVersion::H2) => {
                Some(WsEngine::build(cfg, mode.clone(), shutdown_rx)?)
            }
            _ => None,
        };
        Ok(Self {
            http: Arc::new(http),
            h3,
            ws,
            http_version: cfg.http_version,
            ws_mode: cfg.ws.clone(),
            concurrency: cfg.concurrency,
            mutation,
        })
    }

    pub fn concurrency(&self) -> usize {
        self.concurrency
    }

    /// WS engine access for final drain/reporting.
    pub fn ws(&self) -> Option<&Arc<WsEngine>> {
        self.ws.as_ref()
    }

    /// Execute one intent end-to-end (engine dispatch + telemetry recording
    /// for HTTP work; WS ops record into the WS stats shared cell).
    async fn handle(&self, intent: Intent, telemetry: &Telemetry) {
        match intent.work {
            Work::HttpReq => {
                let intended = intent.intended_send;
                telemetry.enter_flight();
                let out = if let (HttpVersion::H3, Some(h3)) = (self.http_version, self.h3.as_ref())
                {
                    h3.execute(&intent.spec, intended).await
                } else {
                    crate::engine::client::execute_http(self.http.pick(), &intent.spec, intended)
                        .await
                };
                // Mitigation feedback: steer tool selection away from variants
                // that keep getting blocked.
                if let Some(m) = self.mutation.as_ref()
                    && !intent.spec.mitigation_used.is_empty()
                {
                    let blocked = crate::controller::mutation::is_blocked(out.status);
                    m.report_result(&intent.spec.mitigation_used, blocked);
                }
                telemetry.record_flight_end(&out);
            }
            Work::WsOpen => {
                if let Some(ws) = &self.ws {
                    let out = ws.open().await;
                    telemetry.record(&out);
                    telemetry.ws_held_inc();
                }
            }
            Work::WsSend => {
                if let (Some(ws), Some(mode)) = (&self.ws, self.ws_mode.as_ref()) {
                    ws.send(mode.size).await;
                }
            }
            Work::WsClose => {
                if let Some(ws) = &self.ws {
                    ws.close_one().await;
                    telemetry.ws_held_dec();
                }
            }
        }
    }
}

/// Spawn the worker pool plus a scaling supervisor.
///
/// Workers claim exclusivity over the shared receiver (claim → release →
/// execute) and exit once the channel closes and the queue drains. The
/// supervisor grows the pool with the commanded rate using Little's law
/// (`workers ≈ rate × p99`), because a fixed pool starves under a climbing
/// closed-loop rate and worker starvation then masquerades as target
/// saturation in the controller. The pool never shrinks mid-run (tasks are
/// cheap; churn costs more than the memory).
pub fn spawn_workers(
    engine: Arc<Engine>,
    telemetry: Arc<Telemetry>,
    intents_rx: mpsc::Receiver<Intent>,
    max_workers: usize,
    stop: watch::Receiver<bool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let floor = engine.concurrency().max(1);
    let rx = Arc::new(tokio::sync::Mutex::new(intents_rx));
    let handles: Vec<tokio::task::JoinHandle<()>> = (0..floor)
        .map(|_| spawn_one(&engine, &telemetry, &rx))
        .collect();

    // Supervisor: grow-only pool management (Little's law).
    let sup_engine = engine.clone();
    let sup_telemetry = telemetry.clone();
    tokio::spawn(async move {
        let mut live = floor;
        let mut stop = stop;
        while !*stop.borrow_and_update() {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if *stop.borrow() {
                break;
            }
            let snap = sup_telemetry.snapshot();
            let l_s = (snap.p99_ns as f64 / 1e9).clamp(0.005, 5.0);
            let want =
                ((snap.target_rate * l_s).ceil() as usize + 8).clamp(floor, max_workers.max(floor));
            while live < want {
                let h = spawn_one(&sup_engine, &sup_telemetry, &rx);
                drop(h); // detached; workers exit via channel close
                live += 1;
            }
        }
    });

    handles
}

fn spawn_one(
    engine: &Arc<Engine>,
    telemetry: &Arc<Telemetry>,
    rx: &Arc<tokio::sync::Mutex<mpsc::Receiver<Intent>>>,
) -> tokio::task::JoinHandle<()> {
    let engine = engine.clone();
    let telemetry = telemetry.clone();
    let rx = rx.clone();
    tokio::spawn(async move {
        loop {
            // Claim one intent atomically, then execute outside the lock.
            let claimed = {
                let mut guard = rx.lock().await;
                guard.recv().await
            };
            match claimed {
                None => break, // channel closed & drained
                Some(intent) => engine.handle(intent, &telemetry).await,
            }
        }
    })
}
