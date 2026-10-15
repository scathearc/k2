//! Shared integration-test harness: local axum server with controllable
//! behavior (latency injection, 403 storms, big bodies) driving the real K2
//! engine through its library API.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};

/// Any mitigation-family header marks the request as "passed the gate".
fn is_mitigated(h: &HeaderMap) -> bool {
    const NAMES: &[&str] = &[
        "X-Forwarded-For",
        "X-Real-IP",
        "Client-IP",
        "X-Client-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "X-Forwarded-Client-IP",
        "Fastly-Client-IP",
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override",
    ];
    NAMES.iter().any(|n| h.contains_key(*n))
}

#[derive(Debug, Default)]
pub struct HarnessState {
    pub hits: AtomicU64,
    pub latency_ms: AtomicU64,
    pub fail_403_until: AtomicU64,
}

/// Spin the harness on a random loopback port; returns (addr, state, shutdown).
pub async fn spawn() -> (
    SocketAddr,
    Arc<HarnessState>,
    tokio::sync::oneshot::Sender<()>,
) {
    let state = Arc::new(HarnessState::default());
    let app = Router::new()
        .route("/", get(index))
        .route("/late", get(late))
        .route("/storm", get(storm))
        .route("/gate", get(gate))
        .route("/big", get(big))
        .route("/ws", get(ws_upgrade))
        // Mutated paths (/%2e-storm, //storm, …) must still exercise the
        // 403 storm logic, so unknown paths fall through to it as well.
        .fallback(get(storm))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });
    (addr, state, tx)
}

async fn index(State(st): State<Arc<HarnessState>>) -> impl IntoResponse {
    st.hits.fetch_add(1, Ordering::Relaxed);
    Json(serde_json::json!({ "ok": true, "hit": st.hits.load(Ordering::Relaxed) }))
}

async fn late(State(st): State<Arc<HarnessState>>) -> impl IntoResponse {
    st.hits.fetch_add(1, Ordering::Relaxed);
    let ms = st.latency_ms.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(ms.min(5_000))).await;
    Json(serde_json::json!({ "late": true, "ms": ms }))
}

async fn storm(State(st): State<Arc<HarnessState>>) -> impl IntoResponse {
    let n = st.hits.fetch_add(1, Ordering::Relaxed);
    if n < st.fail_403_until.load(Ordering::Relaxed) {
        (StatusCode::FORBIDDEN, "blocked")
    } else {
        (StatusCode::OK, "ok")
    }
}

/// "Under attack mode" endpoint: hard 403 for ANY request that does not carry
/// a mitigation-family header. Simulates a WAF gate that legitimate-looking
/// fixes succeed through — the sticky-mitigation test's target.
async fn gate(hdrs: HeaderMap) -> impl IntoResponse {
    if is_mitigated(&hdrs) {
        (StatusCode::OK, "passed")
    } else {
        (StatusCode::FORBIDDEN, "blocked")
    }
}

async fn big() -> impl IntoResponse {
    vec![0x61u8; 64 * 1024]
}

/// Echo WebSocket: replies to every text/binary frame.
async fn ws_upgrade(
    State(st): State<Arc<HarnessState>>,
    upgrade: WebSocketUpgrade,
) -> axum::response::Response {
    upgrade.on_upgrade(move |socket| ws_loop(socket, st))
}

async fn ws_loop(mut socket: WebSocket, st: Arc<HarnessState>) {
    st.hits.fetch_add(1, Ordering::Relaxed);
    while let Some(Ok(msg)) = socket.recv().await {
        match msg {
            Message::Text(t) => {
                if socket.send(Message::Text(t)).await.is_err() {
                    break;
                }
            }
            Message::Binary(b) => {
                if socket.send(Message::Binary(b)).await.is_err() {
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

/// Build a run Config the same way the CLI does. Callers supply `-d`/`--rate`
/// in `extra` (clap takes the last occurrence).
pub fn config(target: &str, extra: &[&str]) -> k2::Config {
    use clap::Parser as _;
    let mut args = vec!["k2", "--no-tui", target];
    args.extend_from_slice(extra);
    k2::CliArgs::try_parse_from(args)
        .expect("args parse")
        .into_config()
        .expect("config build")
}
