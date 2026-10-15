//! Tokio worker pool dispatcher: pulls intents, runs the right engine,
//! feeds telemetry.

use std::sync::Arc;

use tokio::sync::{mpsc, watch};

use crate::config::{Config, HttpVersion};
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
}

impl Engine {
    pub async fn build(
        cfg: &Config,
        shutdown_rx: watch::Receiver<bool>,
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

/// Spawn `cfg.concurrency` workers consuming the shared intents stream.
/// Workers claim exclusivity over the receiver via the shared mutex (claim →
/// release → execute), and exit once the channel closes and the queue drains.
pub fn spawn_workers(
    engine: Arc<Engine>,
    telemetry: Arc<Telemetry>,
    intents_rx: mpsc::Receiver<Intent>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let n = engine.concurrency().max(1);
    let rx = Arc::new(tokio::sync::Mutex::new(intents_rx));
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let rx = rx.clone();
        let engine = engine.clone();
        let telemetry = telemetry.clone();
        handles.push(tokio::spawn(async move {
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
        }));
    }
    handles
}
