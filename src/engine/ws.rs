//! WebSocket engine: hold large populations of persistent connections, churn
//! them at a controlled rate, and exchange messages while draining inbound
//! stream bodies (frame counts + byte counts only, no parsing).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;
use tokio::sync::Mutex;

use crate::config::{Config, Fidelity, WsMode};
use crate::error::{ErrorKind, K2Result, classify_wreq};
use crate::telemetry::Outcome;
use crate::tls::fingerprints;

/// Live WS population stats for the web/TUI surfaces and the final report.
#[derive(Debug, Clone, Default, Serialize)]
pub struct WsStats {
    pub opened: u64,
    pub closed: u64,
    pub failed: u64,
    pub sent: u64,
    pub frames_rx: u64,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
}

#[derive(Debug, Default)]
pub struct WsStatsShared {
    opened: AtomicU64,
    closed: AtomicU64,
    failed: AtomicU64,
    sent: AtomicU64,
    frames_rx: AtomicU64,
    bytes_rx: AtomicU64,
    bytes_tx: AtomicU64,
    errors: std::sync::Mutex<Vec<(ErrorKind, u64)>>,
}

impl WsStatsShared {
    fn bump(&self, k: &ErrorKind) {
        let mut g = self.errors.lock().unwrap();
        match g.iter_mut().find(|(ek, _)| *ek == *k) {
            Some((_, n)) => *n += 1,
            None => g.push((*k, 1)),
        }
    }
    pub fn error_map(&self) -> Vec<(ErrorKind, u64)> {
        self.errors.lock().unwrap().clone()
    }
}

#[derive(Debug)]
enum WsCmd {
    Send(Vec<u8>),
}

struct Held {
    task: tokio::task::JoinHandle<()>,
    tx: tokio::sync::mpsc::Sender<WsCmd>,
}

/// Engine shared across workers.
pub struct WsEngine {
    mode: WsMode,
    url: String,
    client: wreq::Client,
    fidelity: Fidelity,
    held: Mutex<HashMap<u64, Held>>,
    next_id: AtomicU64,
    stats: Arc<WsStatsShared>,
    shutdown: tokio::sync::watch::Receiver<bool>,
}

impl WsEngine {
    pub fn build(
        cfg: &Config,
        mode: WsMode,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> K2Result<Arc<Self>> {
        let hold = mode.hold as usize;
        let client = crate::engine::client::build_client(cfg)?;
        Ok(Arc::new(Self {
            mode,
            url: cfg.target.clone(),
            client,
            fidelity: cfg.fidelity,
            held: Mutex::new(HashMap::with_capacity(hold)),
            next_id: AtomicU64::new(0),
            stats: Arc::new(WsStatsShared::default()),
            shutdown,
        }))
    }

    pub fn mode(&self) -> &WsMode {
        &self.mode
    }

    pub async fn stats_view(&self) -> (u64, WsStats, Vec<(ErrorKind, u64)>) {
        let held = self.held.lock().await.len() as u64;
        let s = &self.stats;
        (
            held,
            WsStats {
                opened: s.opened.load(Ordering::Relaxed),
                closed: s.closed.load(Ordering::Relaxed),
                failed: s.failed.load(Ordering::Relaxed),
                sent: s.sent.load(Ordering::Relaxed),
                frames_rx: s.frames_rx.load(Ordering::Relaxed),
                bytes_rx: s.bytes_rx.load(Ordering::Relaxed),
                bytes_tx: s.bytes_tx.load(Ordering::Relaxed),
            },
            s.error_map(),
        )
    }

    /// Open one persistent WS connection and hold it.
    pub async fn open(&self) -> Outcome {
        let intended = Instant::now();
        let started = Instant::now();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let url = derive_ws_url(&self.url);

        let mut rb = self.client.websocket(url);
        if let Some(em) = fingerprints::pick(self.fidelity) {
            rb = rb.emulation(em);
        }

        match rb.send().await {
            Ok(resp) => match resp.into_websocket().await {
                Ok(mut ws) => {
                    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<WsCmd>(256);
                    let mut shutdown_rx = self.shutdown.clone();
                    let stats_in = self.stats.clone();
                    let task = tokio::spawn(async move {
                        // Drain inbound frames forever; serve send commands.
                        loop {
                            tokio::select! {
                                cmd = cmd_rx.recv() => match cmd {
                                    Some(WsCmd::Send(bytes)) => {
                                        let n = bytes.len() as u64;
                                        if ws.send(wreq::ws::message::Message::binary(bytes)).await.is_ok() {
                                            stats_in.sent.fetch_add(1, Ordering::Relaxed);
                                            stats_in.bytes_tx.fetch_add(n, Ordering::Relaxed);
                                        } else {
                                            stats_in.failed.fetch_add(1, Ordering::Relaxed);
                                            break;
                                        }
                                    }
                                    None => break,
                                },
                                frame = ws.recv() => match frame {
                                    Some(Ok(msg)) => {
                                        stats_in.frames_rx.fetch_add(1, Ordering::Relaxed);
                                        stats_in.bytes_rx.fetch_add(message_len(&msg) as u64, Ordering::Relaxed);
                                    }
                                    Some(Err(_)) => { stats_in.failed.fetch_add(1, Ordering::Relaxed); break; }
                                    None => break,
                                },
                                _ = shutdown_rx.changed() => break,
                            }
                        }
                    });
                    self.stats.opened.fetch_add(1, Ordering::Relaxed);
                    self.held.lock().await.insert(id, Held { task, tx: cmd_tx });
                    ws_outcome(id, intended, started, None)
                }
                Err(_) => {
                    self.stats.failed.fetch_add(1, Ordering::Relaxed);
                    self.stats.bump(&ErrorKind::Tls);
                    ws_outcome(id, intended, started, Some(ErrorKind::Tls))
                }
            },
            Err(e) => {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
                let kind = classify_wreq(&e);
                self.stats.bump(&kind);
                ws_outcome(id, intended, started, Some(kind))
            }
        }
    }

    /// Send one message into a random held conn.
    pub async fn send(&self, size: usize) {
        let payload = gen_payload(size);
        let held = self.held.lock().await;
        if held.is_empty() {
            return;
        }
        let idx = (rand::random::<u64>() % held.len() as u64) as usize;
        let Some((_, h)) = held.iter().nth(idx) else {
            return;
        };
        // Bounded channel: saturation drops the send (observable via sent counter).
        let _ = h.tx.try_send(WsCmd::Send(payload));
    }

    /// Close (churn) one held conn.
    pub async fn close_one(&self) {
        let mut held = self.held.lock().await;
        if held.is_empty() {
            return;
        }
        let idx = (rand::random::<u64>() % held.len() as u64) as usize;
        let id = held.keys().nth(idx).copied().unwrap();
        if let Some(h) = held.remove(&id) {
            h.task.abort(); // churn semantics: hard close is part of the load
            self.stats.closed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Finalize: close everything.
    pub async fn drain_all(&self) -> WsStats {
        let mut held = self.held.lock().await;
        for (_, h) in held.drain() {
            h.task.abort();
        }
        let s = &self.stats;
        WsStats {
            opened: s.opened.load(Ordering::Relaxed),
            closed: s.closed.load(Ordering::Relaxed),
            failed: s.failed.load(Ordering::Relaxed),
            sent: s.sent.load(Ordering::Relaxed),
            frames_rx: s.frames_rx.load(Ordering::Relaxed),
            bytes_rx: s.bytes_rx.load(Ordering::Relaxed),
            bytes_tx: s.bytes_tx.load(Ordering::Relaxed),
        }
    }
}

fn gen_payload(size: usize) -> Vec<u8> {
    let size = size.clamp(4, 64 * 1024);
    let mut v = vec![0u8; size];
    v[..4].copy_from_slice(&(size as u32).to_be_bytes());
    for b in v[4..].iter_mut() {
        *b = rand::random();
    }
    v
}

fn derive_ws_url(target: &str) -> String {
    if target.starts_with("ws://") || target.starts_with("wss://") {
        return target.to_string();
    }
    if target.starts_with("https://") {
        return target.replacen("https", "wss", 1);
    }
    if target.starts_with("http://") {
        return target.replacen("http", "ws", 1);
    }
    target.to_string()
}

fn message_len(m: &wreq::ws::message::Message) -> usize {
    match m {
        wreq::ws::message::Message::Text(t) => t.len(),
        wreq::ws::message::Message::Binary(b) => b.len(),
        wreq::ws::message::Message::Ping(b) => b.len(),
        wreq::ws::message::Message::Pong(b) => b.len(),
        wreq::ws::message::Message::Close(_) => 0,
    }
}

fn ws_outcome(id: u64, intended: Instant, started: Instant, error: Option<ErrorKind>) -> Outcome {
    // Status 101 (Switching Protocols) marks a successful WS open outcome.
    Outcome {
        seq: id,
        intended_send: intended,
        actual_start: started,
        completed: Instant::now(),
        status: error.as_ref().map_or(Some(101), |_| None),
        error,
        bytes_in: 0,
        bytes_out: 0,
    }
}
