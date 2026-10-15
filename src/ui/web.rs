//! Embedded local web dashboard (axum): WebSocket telemetry at 100ms cadence
//! plus strategy/rate control endpoints — the browser mirror of the TUI.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Router, extract::Path};
use tokio::sync::{mpsc, watch};

use crate::config::StrategyKind;
use crate::controller::ControlMsg;
use crate::telemetry::Telemetry;

const DASHBOARD: &str = include_str!("../../assets/dashboard.html");

type Shared = (Arc<Telemetry>, mpsc::UnboundedSender<ControlMsg>);

pub async fn serve(
    addr: SocketAddr,
    telemetry: Arc<Telemetry>,
    control: mpsc::UnboundedSender<ControlMsg>,
    stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/ws", get(ws_handler))
        .route("/api/strategy/{kind}", get(set_strategy))
        .route("/api/rate/{rate}", get(set_rate))
        .route("/api/drain", get(drain_run))
        .route("/api/entropy", get(toggle_entropy))
        .route("/api/stats", get(stats))
        .with_state((telemetry, control));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let mut shutdown = stop;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            while !*shutdown.borrow() {
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
}

async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD)
}

async fn set_strategy(State(shared): State<Shared>, Path(kind): Path<String>) -> Response {
    let kind = match kind.as_str() {
        "fixed" => Some(StrategyKind::Fixed),
        "knee" => Some(StrategyKind::Knee),
        "pulse" => Some(StrategyKind::Pulse),
        "brownout" => Some(StrategyKind::Brownout),
        "manual" => Some(StrategyKind::Manual),
        _ => None,
    };
    match kind {
        Some(k) => {
            let _ = shared.1.send(ControlMsg::SetStrategy(k));
            (StatusCode::OK, "ok").into_response()
        }
        None => (StatusCode::BAD_REQUEST, "unknown strategy").into_response(),
    }
}

async fn set_rate(State(shared): State<Shared>, Path(rate): Path<String>) -> Response {
    // forms: "1234" or "+100" / "-100"
    let msg = if let Some(d) = rate.strip_prefix('+') {
        match d.parse::<f64>() {
            Ok(v) => ControlMsg::AdjustRate(v),
            Err(_) => return (StatusCode::BAD_REQUEST, "bad delta").into_response(),
        }
    } else if let Some(d) = rate.strip_prefix('-') {
        match d.parse::<f64>() {
            Ok(v) => ControlMsg::AdjustRate(-v),
            Err(_) => return (StatusCode::BAD_REQUEST, "bad delta").into_response(),
        }
    } else {
        match rate.parse::<f64>() {
            Ok(v) => ControlMsg::SetRate(v),
            Err(_) => return (StatusCode::BAD_REQUEST, "bad rate").into_response(),
        }
    };
    let _ = shared.1.send(msg);
    (StatusCode::OK, "ok").into_response()
}

async fn drain_run(State(shared): State<Shared>) -> Response {
    let _ = shared.1.send(ControlMsg::Quit);
    (StatusCode::OK, "drain requested").into_response()
}

async fn toggle_entropy(State(shared): State<Shared>) -> Response {
    let _ = shared.1.send(ControlMsg::ToggleEntropy);
    (StatusCode::OK, "toggled").into_response()
}

async fn stats(State(shared): State<Shared>) -> Response {
    let snap = shared.0.snapshot();
    Json(snap).into_response()
}

async fn ws_handler(State(shared): State<Shared>, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| ws_loop(socket, shared.0))
}

async fn ws_loop(mut socket: WebSocket, telemetry: Arc<Telemetry>) {
    let mut iv = tokio::time::interval(std::time::Duration::from_millis(crate::telemetry::TICK_MS));
    iv.tick().await;
    loop {
        iv.tick().await;
        let snap = telemetry.snapshot();
        let body = match serde_json::to_string(&snap) {
            Ok(b) => b,
            Err(_) => break,
        };
        if socket.send(WsMessage::Text(body.into())).await.is_err() {
            break;
        }
        // Non-blocking drain of client frames; close frames terminate the feed.
        loop {
            let recv_fut = std::pin::pin!(socket.recv());
            match futures::poll!(recv_fut) {
                std::task::Poll::Ready(Some(Ok(WsMessage::Close(_)))) => return,
                std::task::Poll::Ready(None) => return,
                std::task::Poll::Ready(Some(Err(_))) => return,
                std::task::Poll::Ready(Some(Ok(_))) => continue,
                std::task::Poll::Pending => break,
            }
        }
    }
}
