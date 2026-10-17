//! HTTP/3 (QUIC) engine built on quinn + h3, with TLS verification bypass,
//! X25519-only key exchange, and direct UDP or SOCKS5-UDP-ASSOCIATE transport.
//!
//! One maximally-multiplexed H3 connection is kept per endpoint (per HTTP/3
//! spec rationale: clients SHOULD use a single connection); `SendRequest` is
//! cloned per request. Failed connections are re-established lazily.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::{Buf, Bytes};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::CipherSuite;
use rustls::crypto::ring;
use tokio::net::UdpSocket;

use crate::config::Config;
use crate::engine::request::RequestSpec;
use crate::engine::socks5::{Socks5Spec, Socks5UdpSocket, udp_associate};
use crate::error::{ErrorKind, K2Error, K2Result};
use crate::telemetry::Outcome;
use crate::tls::verifier::NoVerify;

/// H3 engine.
pub struct H3Engine {
    qtls: quinn::ClientConfig,
    runtime: Arc<quinn::TokioRuntime>,
    endpoint: std::sync::OnceLock<quinn::Endpoint>,
    conns: std::sync::Mutex<Option<H3Conn>>,
    server_addr: SocketAddr,
    server_name: String,
    proxy: Option<Arc<Socks5Spec>>,
    bind: Option<std::net::IpAddr>,
}

struct H3Conn {
    qconn: quinn::Connection,
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
}

impl H3Engine {
    pub async fn build(cfg: &Config) -> K2Result<Arc<Self>> {
        // H3 keeps one multiplexed connection per endpoint, and the endpoint
        // binds its UDP socket once. AnyIP rotation is therefore not available
        // on H3 — refuse loudly rather than silently ignoring the flag.
        if cfg.bind_net.is_some() {
            return Err(K2Error::Config(
                "--bind-net (AnyIP source rotation) is not supported for HTTP/3: \
                 H3 binds a single UDP socket for the whole run. \
                 Use --bind <ip> to pin, or run H1/H2 for per-request rotation."
                    .into(),
            ));
        }
        let (server_addr, server_name) = resolve_target(cfg).await?;
        let qtls = h3_tls_config(cfg.tls_verify)?;
        let proxy = cfg
            .proxy
            .clone()
            .map(|p| Socks5Spec::parse(&p))
            .transpose()?
            .map(Arc::new);
        Ok(Arc::new(Self {
            qtls,
            runtime: Arc::new(quinn::TokioRuntime),
            endpoint: std::sync::OnceLock::new(),
            conns: std::sync::Mutex::new(None),
            server_addr,
            server_name,
            proxy,
            bind: cfg.bind,
        }))
    }

    async fn endpoint(&self) -> K2Result<&quinn::Endpoint> {
        if let Some(e) = self.endpoint.get() {
            return Ok(e);
        }
        let endpoint = match &self.proxy {
            None => {
                let bind_addr = bind_for(&self.server_addr, self.bind, None);
                let socket = std::net::UdpSocket::bind(bind_addr)?;
                quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    None,
                    socket,
                    self.runtime.clone(),
                )
                .map_err(K2Error::Io)?
            }
            Some(spec) => {
                let association = udp_associate(spec).await?;
                let relay = association.relay;
                let bind_addr = bind_for(&self.server_addr, self.bind, Some(relay));
                let udp = Arc::new(UdpSocket::bind(bind_addr).await?);
                let sock = Socks5UdpSocket::new(udp, association, relay);
                quinn::Endpoint::new_with_abstract_socket(
                    quinn::EndpointConfig::default(),
                    None,
                    Arc::new(sock),
                    self.runtime.clone(),
                )
                .map_err(K2Error::Io)?
            }
        };
        // First-set wins after that (successors leak-compatible clones).
        let _ = self.endpoint.set(endpoint.clone());
        self.endpoint
            .get()
            .ok_or_else(|| K2Error::Engine("endpoint race".into()))
    }

    async fn connect(&self) -> K2Result<H3Conn> {
        let mut endpoint = self.endpoint().await?.clone();
        endpoint.set_default_client_config(self.qtls.clone());
        let qconn = endpoint
            .connect(self.server_addr, &self.server_name)
            .map_err(|e| K2Error::Engine(format!("connect: {e}")))?
            .await
            .map_err(|e| K2Error::Engine(format!("quic handshake: {e}")))?;
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(qconn.clone()))
            .await
            .map_err(|e| K2Error::Engine(format!("h3 setup: {e}")))?;
        // Drive the H3 connection state machine until it closes.
        tokio::spawn(async move {
            let _: h3::error::ConnectionError =
                std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        Ok(H3Conn { qconn, send })
    }

    async fn send_slot(&self) -> K2Result<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>> {
        {
            let guard = self.conns.lock().unwrap();
            if let Some(c) = guard.as_ref() {
                return Ok(c.send.clone());
            }
        }
        let conn = self.connect().await?;
        let send = conn.send.clone();
        *self.conns.lock().unwrap() = Some(conn);
        Ok(send)
    }

    /// Execute one request cycle over H3. One retry on dead connection.
    pub async fn execute(&self, spec: &RequestSpec, intended: Instant) -> Outcome {
        for attempt in 0..2u8 {
            let mut send = match self.send_slot().await {
                Ok(s) => s,
                Err(e) => return err_outcome(spec, intended, Instant::now(), errout(&e)),
            };
            let outcome = self.drive_one(&mut send, spec, intended).await;
            match &outcome.error {
                // Non-timeout transport errors: presumed dead conn — recreate once.
                Some(kind) if !matches!(kind, ErrorKind::Timeout) && attempt == 0 => {
                    let mut g = self.conns.lock().unwrap();
                    if let Some(c) = g.take() {
                        c.qconn.close(0u32.into(), b"k2 reconnect");
                    }
                    continue;
                }
                _ => return outcome,
            }
        }
        unreachable!("retry bound exhausted via early returns")
    }

    async fn drive_one(
        &self,
        send: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        spec: &RequestSpec,
        intended: Instant,
    ) -> Outcome {
        let started = Instant::now();
        let method = match http::Method::from_bytes(spec.method.as_bytes()) {
            Ok(m) => m,
            Err(_) => return err_outcome(spec, intended, started, ErrorKind::Proto),
        };
        let uri = match spec.url.parse::<http::Uri>() {
            Ok(u) => u,
            Err(_) => return err_outcome(spec, intended, started, ErrorKind::Proto),
        };
        let mut rb = http::Request::builder().method(method).uri(uri);
        for (k, v) in &spec.headers {
            rb = rb.header(k, v);
        }
        let req = match rb.body(()) {
            Ok(r) => r,
            Err(e) => return err_outcome(spec, intended, started, proto_from_http(e)),
        };

        let mut stream = match send.send_request(req).await {
            Ok(s) => s,
            Err(e) => return err_outcome(spec, intended, started, classify_h3_stream(&e)),
        };
        if let Some(body) = &spec.body
            && let Err(e) = stream.send_data(Bytes::from(body.clone())).await
        {
            return err_outcome(spec, intended, started, classify_h3_stream(&e));
        }
        if let Err(e) = stream.finish().await {
            return err_outcome(spec, intended, started, classify_h3_stream(&e));
        }

        let resp = match stream.recv_response().await {
            Ok(r) => r,
            Err(e) => return err_outcome(spec, intended, started, classify_h3_stream(&e)),
        };
        let status = resp.status().as_u16();

        // Zero-allocation body drain: count-only reads through fixed scratch.
        let mut total_bytes = 0u64;
        loop {
            match stream.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let n = chunk.remaining();
                    touch_scratch(&mut chunk);
                    total_bytes = total_bytes.saturating_add(n as u64);
                }
                Ok(None) => break,
                Err(e) => return err_outcome(spec, intended, started, classify_h3_stream(&e)),
            }
        }

        Outcome {
            seq: spec.seq,
            intended_send: intended,
            actual_start: started,
            completed: Instant::now(),
            status: Some(status),
            error: None,
            bytes_in: total_bytes,
            bytes_out: spec.body.as_ref().map(|b| b.len() as u64).unwrap_or(0),
        }
    }
}

fn errout(e: &K2Error) -> ErrorKind {
    match e {
        K2Error::Proxy(_) => ErrorKind::Proxy,
        K2Error::Io(_) => ErrorKind::Io,
        K2Error::Config(_) | K2Error::Engine(_) => ErrorKind::Proto,
    }
}

fn proto_from_http(_e: http::Error) -> ErrorKind {
    ErrorKind::Proto
}

/// Zero-alloc drain: touch the payload in a fixed thread-local 8KB block.
fn touch_scratch(buf: &mut impl bytes::Buf) {
    const SCRATCH_BYTES: usize = 8 * 1024;
    thread_local! {
        static SCRATCH: std::cell::RefCell<Box<[u8; SCRATCH_BYTES]>> =
            std::cell::RefCell::new(Box::new([0u8; SCRATCH_BYTES]));
    }
    while buf.has_remaining() {
        let data = buf.chunk();
        let n = data.len().min(SCRATCH_BYTES);
        SCRATCH.with(|cell| {
            let mut borrow = cell.borrow_mut();
            let b: &mut [u8] = &mut borrow[..];
            b[..n].copy_from_slice(&data[..n]);
        });
        buf.advance(n);
    }
}

fn bind_for(
    server: &SocketAddr,
    bind: Option<std::net::IpAddr>,
    relay: Option<SocketAddr>,
) -> SocketAddr {
    // When tunnelling through a SOCKS5 relay, the local UDP socket must share
    // the relay's address family — an IPv6 socket cannot sendmsg() to an IPv4
    // relay (EINVAL). The server's family is irrelevant in that case.
    if let Some(r) = relay {
        return SocketAddr::new(r.ip(), 0);
    }
    match bind {
        // Explicit source IP: keep the server's family.
        Some(ip) if ip.is_ipv4() == server.is_ipv4() => SocketAddr::new(ip, 0),
        Some(ip) => SocketAddr::new(ip, 0),
        None => {
            if server.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            }
        }
    }
}

/// A BoringSSL-fidelity-adjacent rustls provider: X25519-only key exchange
/// and the TLS 1.3 AES-128-GCM suite only.
fn x25519_ring_provider() -> rustls::crypto::CryptoProvider {
    let mut p = ring::default_provider();
    p.kx_groups
        .retain(|g| g.name() == rustls::NamedGroup::X25519);
    p.cipher_suites
        .retain(|cs| cs.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256);
    p
}

/// HTTP/3 client TLS config: ring provider, X25519-only, TLS13-only,
/// default cert-verification bypass or real roots with `--tls-verify`.
fn h3_tls_config(verify: bool) -> K2Result<quinn::ClientConfig> {
    let wire_provider = x25519_ring_provider();

    let tls = {
        let builder = rustls::ClientConfig::builder_with_provider(wire_provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| K2Error::Engine(format!("tls versions: {e}")))?;
        if verify {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            builder.with_root_certificates(roots).with_no_client_auth()
        } else {
            let verifier_provider = x25519_ring_provider();
            builder
                .dangerous()
                .with_custom_certificate_verifier(NoVerify::boxed(&verifier_provider))
                .with_no_client_auth()
        }
    };

    let mut tls = tls;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).map_err(|e| K2Error::Engine(format!("quinn tls: {e}")))?,
    )))
}

async fn resolve_target(cfg: &Config) -> K2Result<(SocketAddr, String)> {
    let host = authority_host(cfg)?;
    let port = authority_port(cfg, 443);
    let literal = host.clone().parse::<std::net::IpAddr>().ok();
    if let Some(ip) = literal {
        return Ok((SocketAddr::new(ip, port), host));
    }
    let mut it = tokio::net::lookup_host((host.clone(), port))
        .await
        .map_err(|e| K2Error::Config(format!("dns: {e}")))?;
    match it.next() {
        Some(a) => Ok((a, host)),
        None => Err(K2Error::Config(format!("dns: no addresses for {host}"))),
    }
}

/// Extract absolute host from the target.
fn authority_host(cfg: &Config) -> K2Result<String> {
    let Some((_, rest)) = cfg.target.split_once("://") else {
        return Err(K2Error::Config("no scheme".into()));
    };
    let end = rest.find('/').unwrap_or(rest.len());
    let authority = rest[..end].rsplit('@').next().unwrap_or(rest);
    // strip any IPv6 presentation brackets, then drop a trailing :port
    let bracketed = authority.starts_with('[');
    let host = if bracketed {
        let inner = authority.trim_matches(|c: char| c == '[' || c == ']');
        inner.split(']').next().unwrap_or(inner)
    } else {
        match authority.rsplit_once(':') {
            Some((h, _p)) => h,
            None => authority,
        }
    };
    let host = host.trim();
    if host.is_empty() {
        return Err(K2Error::Config("no host".into()));
    }
    Ok(host.to_string())
}

fn authority_port(cfg: &Config, default: u16) -> u16 {
    let Some((_, rest)) = cfg.target.split_once("://") else {
        return default;
    };
    let end = rest.find('/').unwrap_or(rest.len());
    let authority = rest[..end].rsplit('@').next().unwrap_or(rest);
    if authority.starts_with('[') {
        // [v6:pct?]:port — bracketed host: take after last ']' before ':'
        return authority
            .rsplit_once("]:")
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(default);
    }
    match authority.rsplit_once(':') {
        Some((_, p)) => p.parse().unwrap_or(default),
        None => default,
    }
}

/// h3 exposes stream/connection failure kinds without public variant access;
/// classify from the Debug/Display shape.
fn classify_h3_stream(e: &h3::error::StreamError) -> ErrorKind {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = write!(s, "{e:?}");
    let s = s.to_ascii_lowercase();
    if s.contains("timeout") {
        ErrorKind::Timeout
    } else if s.contains("remote")
        || s.contains("reset")
        || s.contains("stream error")
        || s.contains("stopping")
        || s.contains("closing")
        || s.contains("connection")
    {
        ErrorKind::Reset
    } else {
        ErrorKind::Io
    }
}

fn err_outcome(
    spec: &RequestSpec,
    intended: Instant,
    started: Instant,
    kind: ErrorKind,
) -> Outcome {
    Outcome {
        seq: spec.seq,
        intended_send: intended,
        actual_start: started,
        completed: Instant::now(),
        status: None,
        error: Some(kind),
        bytes_in: 0,
        bytes_out: 0,
    }
}
