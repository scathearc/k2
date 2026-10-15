use std::time::Duration;

use thiserror::Error;

/// On-the-wire / transport failure taxonomy for telemetry classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Connect,
    Timeout,
    Reset,
    Dns,
    Proxy,
    Tls,
    Proto,
    Io,
    Blocked,
    Cancelled,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ErrorKind::Connect => "connect",
            ErrorKind::Timeout => "timeout",
            ErrorKind::Reset => "reset",
            ErrorKind::Dns => "dns",
            ErrorKind::Proxy => "proxy",
            ErrorKind::Tls => "tls",
            ErrorKind::Proto => "proto",
            ErrorKind::Io => "io",
            ErrorKind::Blocked => "blocked",
            ErrorKind::Cancelled => "cancelled",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Error)]
pub enum K2Error {
    #[error("config: {0}")]
    Config(String),
    #[error("engine: {0}")]
    Engine(String),
    #[error("proxy: {0}")]
    Proxy(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type K2Result<T> = Result<T, K2Error>;

/// Classifies a wreq error into our taxonomy by inspecting its predicates.
pub fn classify_wreq(err: &wreq::Error) -> ErrorKind {
    if err.is_timeout() {
        return ErrorKind::Timeout;
    }
    if err.is_connect() {
        return ErrorKind::Connect;
    }
    if err.is_request() {
        // request-phase failure: could be proxy refusal or serializer builder issue
        if err.to_string().contains("proxy") {
            return ErrorKind::Proxy;
        }
        return ErrorKind::Proto;
    }
    if err.is_body() || err.is_decode() {
        return ErrorKind::Reset;
    }
    if err.is_builder() {
        return ErrorKind::Proto;
    }
    if err.is_redirect() {
        return ErrorKind::Proto;
    }
    ErrorKind::Io
}

/// Classifies quinn/h3 connection errors.
pub fn classify_quick(err: &quinn::ConnectionError) -> ErrorKind {
    use quinn::ConnectionError as E;
    match err {
        E::TimedOut => ErrorKind::Timeout,
        E::VersionMismatch => ErrorKind::Proto,
        E::ApplicationClosed(_) => ErrorKind::Reset,
        E::Reset => ErrorKind::Reset,
        E::ConnectionClosed(_) | E::CidsExhausted => ErrorKind::Reset,
        E::TransportError(e) => {
            let s = format!("{e}");
            if s.contains("NO_ERROR") || s.contains("APPLICATION_ERROR") {
                ErrorKind::Reset
            } else {
                ErrorKind::Proto
            }
        }
        _ => ErrorKind::Io,
    }
}

/// Sanitizes a connect timeout so caller mistakes can't produce 0s hangs.
pub fn sane_timeout(d: Duration) -> Duration {
    if d.is_zero() {
        Duration::from_secs(10)
    } else {
        d
    }
}
