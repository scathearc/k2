//! wreq client construction and the per-worker client pool (H1/H2 engine).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::config::Config;
use crate::engine::drain;
use crate::engine::request::RequestSpec;
use crate::error::{K2Error, K2Result, classify_wreq};
use crate::telemetry::Outcome;
use crate::tls::fingerprints;

/// A round-robin pool of independently built wreq clients. Each client keeps
/// its own hyper connection pool, so per-request emulation selection never
/// tears down unrelated keep-alive sockets.
pub struct WreqPool {
    clients: Vec<wreq::Client>,
    rr: AtomicU64,
}

impl WreqPool {
    pub fn build(cfg: &Config) -> K2Result<Self> {
        let mut clients = Vec::with_capacity(cfg.concurrency);
        for _ in 0..cfg.concurrency {
            clients.push(build_client(cfg)?);
        }
        Ok(Self {
            clients,
            rr: AtomicU64::new(0),
        })
    }

    pub fn pick(&self) -> &wreq::Client {
        let i = self.rr.fetch_add(1, Ordering::Relaxed) % self.clients.len() as u64;
        &self.clients[i as usize]
    }
}

pub fn build_client(cfg: &Config) -> K2Result<wreq::Client> {
    let mut b = wreq::Client::builder();

    // TLS: bypass is default (client-CPU efficiency directive); --tls-verify restores it.
    b = b.tls_cert_verification(cfg.tls_verify);
    if !cfg.tls_verify {
        b = b.tls_verify_hostname(false);
    }

    // Version pinning for h1/h2 selection (ALPN still flows otherwise).
    {}
    match cfg.http_version {
        crate::config::HttpVersion::H1 => b = b.http1_only(),
        crate::config::HttpVersion::H2 => b = b.http2_only(),
        _ => {}
    }

    if let Some(t) = cfg.timeout {
        b = b.timeout(t);
    }
    b = b.connect_timeout(cfg.connect_timeout);
    b = b.read_timeout(cfg.timeout.unwrap_or(Duration::from_secs(30)));

    // Long-lived pooling: never dispose healthy keep-alive sockets mid-run.
    b = b.pool_idle_timeout(Duration::from_secs(600));
    b = b.pool_max_idle_per_host(64);
    b = b.pool_max_size(1024);
    b = b.tcp_nodelay(true);

    if let Some(proxy) = &cfg.proxy {
        // wreq parses socks5://user:pass@host:port authentication from URL.
        let p = wreq::Proxy::all(proxy).map_err(|e| K2Error::Proxy(format!("{e}")))?;
        b = b.proxy(p);
    }

    // Source-IP surface (AnyIP / local address pinning). When a --bind-net
    // CIDR is configured the bind is per-request (see execute_http); only a
    // bare --bind is a client-level pin.
    if let Some(ip) = cfg.bind
        && cfg.bind_net.is_none()
    {
        b = b.local_address(ip);
    }

    // Browsers follow redirects coherently; bound to a sane hop count.
    b = b.redirect(wreq::redirect::Policy::limited(16));

    b.build()
        .map_err(|e| K2Error::Engine(format!("wreq client: {e}")))
}

/// Execute one `Work::HttpReq` via the wreq (H1/H2) engine.
pub async fn execute_http(
    client: &wreq::Client,
    spec: &RequestSpec,
    intended: std::time::Instant,
) -> Outcome {
    let started = std::time::Instant::now();

    let method = match http::Method::from_bytes(spec.method.as_bytes()) {
        Ok(m) => m,
        Err(_) => return outcome_err(spec, intended, started, crate::error::ErrorKind::Proto),
    };

    // Randomized fingerprint per request: a coherent browser profile picked
    // per dispatch (per fresh TLS connection effectively).
    let mut rb = client.request(method, spec.url.as_str());
    // AnyIP source rotation: pick a fresh source address per request.
    if let Some(ip) = spec.bind {
        rb = rb.local_address(ip);
    }
    if let Some(em) = fingerprints::pick(spec.fidelity) {
        rb = rb.emulation(em);
    }
    for (k, v) in &spec.headers {
        rb = rb.header(k, v);
    }
    if let Some(body) = &spec.body {
        rb = rb.body(body.clone());
    }

    match rb.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let (bytes_in, drain_err) = drain::drain(resp).await;
            let completed = std::time::Instant::now();
            match drain_err {
                None => Outcome {
                    seq: spec.seq,
                    intended_send: intended,
                    actual_start: started,
                    completed,
                    status: Some(status),
                    error: None,
                    bytes_in,
                    bytes_out: spec.body.as_ref().map(|b| b.len() as u64).unwrap_or(0),
                },
                Some(kind) => Outcome {
                    seq: spec.seq,
                    intended_send: intended,
                    actual_start: started,
                    completed,
                    status: None,
                    error: Some(kind),
                    bytes_in,
                    bytes_out: 0,
                },
            }
        }
        Err(e) => outcome_err(spec, intended, started, classify_wreq(&e)),
    }
}

fn outcome_err(
    spec: &RequestSpec,
    intended: std::time::Instant,
    started: std::time::Instant,
    kind: crate::error::ErrorKind,
) -> Outcome {
    Outcome {
        seq: spec.seq,
        intended_send: intended,
        actual_start: started,
        completed: std::time::Instant::now(),
        status: None,
        error: Some(kind),
        bytes_in: 0,
        bytes_out: 0,
    }
}
