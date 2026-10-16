//! Node-server mode: a k2 process inside a swarm sandbox that receives its
//! campaign configuration from the coordinator, executes it locally, and
//! serves cumulative telemetry snapshots over a public sandbox URL.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use tokio::sync::{mpsc, watch};

use crate::config::Config;
use crate::engine::Front;
use crate::engine::pool::{Engine, spawn_workers};
use crate::engine::scheduler::Scheduler;
use crate::telemetry::{TICK_MS, Telemetry, TickData};

/// Shared node state driven by the coordinator's HTTP calls.
pub struct NodeState {
    pub node_id: AtomicU64,
    config: Mutex<Option<Config>>,
    rate_tx: watch::Sender<f64>,
    pub rate_rx: watch::Receiver<f64>,
    stop_tx: watch::Sender<bool>,
    pub stop_rx: watch::Receiver<bool>,
    configured: AtomicBool,
    telemetry: Arc<Telemetry>,
    run_done: AtomicBool,
}

type NodeShared = Arc<NodeState>;

impl NodeState {
    pub fn new() -> Arc<Self> {
        let (rate_tx, rate_rx) = watch::channel(0.0);
        let (stop_tx, stop_rx) = watch::channel(false);
        Arc::new(Self {
            node_id: AtomicU64::new(0),
            config: Mutex::new(None),
            rate_tx,
            rate_rx,
            stop_tx,
            stop_rx,
            configured: AtomicBool::new(false),
            telemetry: Arc::new(Telemetry::new()),
            run_done: AtomicBool::new(false),
        })
    }

    pub fn telemetry(&self) -> Arc<Telemetry> {
        self.telemetry.clone()
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct ConfigureBody {
    pub node_id: u64,
    pub config: Config,
}

/// Serve the node control surface on an already-bound listener; blocks until
/// the process should exit. The caller owns port selection (use `:0` for an
/// OS-assigned port — the FakeProvider does this to avoid collisions across
/// test runs).
pub async fn serve_with_listener(listener: tokio::net::TcpListener) -> crate::error::K2Result<()> {
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(_) => 0,
    };
    serve_inner(port, listener).await
}

/// Bind on `port` and serve; blocks until the process should exit.
pub async fn serve(port: u16) -> crate::error::K2Result<()> {
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .map_err(crate::error::K2Error::Io)?;
    serve_inner(port, listener).await
}

async fn serve_inner(port: u16, listener: tokio::net::TcpListener) -> crate::error::K2Result<()> {
    let state = NodeState::new();
    let run_state = state.clone();

    // Campaign runner: waits for /configure, then runs until done or drained.
    tokio::spawn(async move {
        while !run_state.configured.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let cfg = run_state
            .config
            .lock()
            .unwrap()
            .clone()
            .expect("configured");
        let node_id = run_state.node_id.load(Ordering::SeqCst);
        let telemetry = run_state.telemetry();

        let front = match Front::new(&cfg) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("node {node_id}: campaign setup failed: {e}");
                return;
            }
        };
        let engine = match Engine::build(
            &cfg,
            run_state.stop_rx.clone(),
            Some(front.mutation.clone()),
        )
        .await
        {
            Ok(e) => Arc::new(e),
            Err(e) => {
                tracing::error!("node {node_id}: engine build failed: {e}");
                return;
            }
        };

        let (intents_tx, intents_rx) =
            mpsc::channel::<crate::engine::Intent>((cfg.concurrency * 16).clamp(64, 16384));
        let scheduler = Scheduler {
            cfg: Arc::new(cfg.clone()),
            materializer: front.materializer.clone(),
            intents_tx,
            rate_rx: run_state.rate_rx.clone(),
            telemetry: telemetry.clone(),
            stop_rx: run_state.stop_rx.clone(),
        };
        let workers = spawn_workers(
            engine,
            telemetry.clone(),
            intents_rx,
            cfg.max_workers,
            run_state.stop_rx.clone(),
        );

        // Node heartbeat: maintain cumulative telemetry; no controller here —
        // the coordinator owns the closed loop.
        let hb = {
            let telemetry = telemetry.clone();
            let stop = run_state.stop_rx.clone();
            let mut rate_rx = run_state.rate_rx.clone();
            tokio::spawn(async move {
                let mut iv = tokio::time::interval(Duration::from_millis(TICK_MS));
                iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                iv.tick().await;
                while !*stop.borrow() {
                    iv.tick().await;
                    if *stop.borrow() {
                        break;
                    }
                    let td: TickData = telemetry.begin_tick();
                    telemetry.set_target_rate(*rate_rx.borrow_and_update());
                    telemetry.finish_tick(td);
                }
            })
        };

        let scheduler_task = tokio::spawn(scheduler.run());
        let _ = scheduler_task.await;
        let _ = run_state.stop_tx.send(true);
        for w in workers {
            let _ = w.await;
        }
        let _ = hb.await;
        run_state.run_done.store(true, Ordering::SeqCst);
        tracing::info!("node {node_id}: campaign complete");
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/configure", post(configure))
        .route("/snapshot", get(snapshot))
        .route("/rate", post(set_rate))
        .route("/drain", post(drain))
        .with_state(state);

    tracing::info!("node server listening on :{port}");
    axum::serve(listener, app)
        .await
        .map_err(crate::error::K2Error::Io)
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn configure(
    State(state): State<NodeShared>,
    Json(body): Json<ConfigureBody>,
) -> impl IntoResponse {
    if state.configured.swap(true, Ordering::SeqCst) {
        return (StatusCode::CONFLICT, "already configured");
    }
    state.node_id.store(body.node_id, Ordering::SeqCst);
    *state.config.lock().unwrap() = Some(body.config);
    (StatusCode::OK, "configured")
}

async fn snapshot(State(state): State<NodeShared>) -> impl IntoResponse {
    if !state.configured.load(Ordering::SeqCst) {
        return (
            StatusCode::CONFLICT,
            Json(None::<crate::swarm::ingest::IngestPayload>),
        )
            .into_response();
    }
    let node = state.node_id.load(Ordering::SeqCst);
    let mut p = state.telemetry().ingest_payload(node);
    p.done = state.run_done.load(Ordering::SeqCst);
    Json(Some(p)).into_response()
}

#[derive(Debug, serde::Deserialize)]
pub struct RateBody {
    pub rate: f64,
}

async fn set_rate(
    State(state): State<NodeShared>,
    Json(body): Json<RateBody>,
) -> impl IntoResponse {
    let _ = state.rate_tx.send(body.rate);
    (StatusCode::OK, "ok")
}

async fn drain(State(state): State<NodeShared>) -> impl IntoResponse {
    let _ = state.stop_tx.send(true);
    (StatusCode::OK, "draining")
}
