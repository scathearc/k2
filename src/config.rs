use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, ValueEnum};

/// K2: closed-loop, browser-fidelity load testing engine.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "k2",
    version,
    about = "K2 — closed-loop adaptive load engine (use only on authorized targets)",
    after_help = crate::AUTHORIZED_USE
)]
pub struct CliArgs {
    /// Target URL. Supports random charclass templates: https://t.local/api/[a-z][1-9]?q=[a-f]
    pub target: String,

    /// Total number of requests to issue (0 = unlimited)
    #[arg(short = 'n', long, default_value_t = 0)]
    pub requests: u64,

    /// Run duration in seconds (0 = until request count is satisfied)
    #[arg(short = 'd', long, default_value_t = 10.0)]
    pub duration: f64,

    /// Worker concurrency (number of in-flight workers)
    #[arg(short = 'c', long, default_value_t = default_concurrency())]
    pub concurrency: usize,

    /// Fixed target requests/second. If omitted, defaults to closed-loop Knee (AIMD) hunting
    #[arg(long)]
    pub rate: Option<u64>,

    /// Local source IP to bind outbound sockets (TCP clients + H3 UDP).
    /// Requires a routable local address (AnyIP setups need CAP_NET_ADMIN).
    #[arg(long, value_name = "IP")]
    pub bind: Option<std::net::IpAddr>,

    /// Poisson (exponentially distributed) arrival jitter instead of uniform pacing
    #[arg(long)]
    pub poisson: bool,

    /// HTTP method
    #[arg(short = 'X', long, default_value = "GET")]
    pub method: String,

    /// Custom headers (repeatable): -H 'X-Debug: 1'
    #[arg(short = 'H', long = "header")]
    pub headers: Vec<String>,

    /// Request body (verbatim)
    #[arg(long)]
    pub body: Option<String>,

    /// Request body from file
    #[arg(long)]
    pub body_file: Option<String>,

    /// Content-Type short form (superseded by explicit -H)
    #[arg(long)]
    pub content_type: Option<String>,

    /// HTTP version: auto | h1 | h2 | h3
    #[arg(long, value_enum, default_value_t = HttpVersion::Auto)]
    pub http_version: HttpVersion,

    /// Verify TLS certificates (cert verification bypass is ON by default for CPU efficiency)
    #[arg(long)]
    pub tls_verify: bool,

    /// Browser fidelity profile: chrome | firefox | safari | edge | opera | okhttp | random | none
    #[arg(long, value_enum, default_value_t = Fidelity::Random)]
    pub fidelity: Fidelity,

    /// SOCKS5 or HTTP CONNECT proxy: socks5://user:pass@host:port or http://host:port
    #[arg(short = 'x', long)]
    pub proxy: Option<String>,

    /// Per-request timeout in seconds (0 disables)
    #[arg(long, default_value_t = 30.0)]
    pub timeout: f64,

    /// Connect timeout in seconds
    #[arg(long, default_value_t = 10.0)]
    pub connect_timeout: f64,

    /// Control strategy: fixed | knee | pulse | brownout | manual
    #[arg(long, value_enum)]
    pub strategy: Option<StrategyKind>,

    /// AIMD additive increase per tick (requests/sec)
    #[arg(long, default_value_t = 100.0)]
    pub aimd_alpha: f64,

    /// AIMD multiplicative decrease factor (0 < beta < 1)
    #[arg(long, default_value_t = 0.75)]
    pub aimd_beta: f64,

    /// AIMD latency-derivative threshold (relative dLat/dt per second)
    #[arg(long, default_value_t = 0.35)]
    pub aimd_delta: f64,

    /// Minimum AIMD rate floor (requests/sec)
    #[arg(long, default_value_t = 1.0)]
    pub aimd_min_rate: f64,

    /// Maximum AIMD rate ceiling (requests/sec)
    #[arg(long, default_value_t = 100_000.0)]
    pub aimd_max_rate: f64,

    /// Pulse period seconds (square wave)
    #[arg(long, default_value_t = 5.0)]
    pub pulse_period: f64,

    /// Pulse duty cycle (fraction of period at high rate)
    #[arg(long, default_value_t = 0.7)]
    pub pulse_duty: f64,

    /// Pulse high rate (requests/sec)
    #[arg(long, default_value_t = 1000.0)]
    pub pulse_hi: f64,

    /// Pulse low rate (requests/sec)
    #[arg(long, default_value_t = 100.0)]
    pub pulse_lo: f64,

    /// Brownout: fraction of knee-peak rate to sustain (0-1]
    #[arg(long, default_value_t = 0.6)]
    pub brownout_pct: f64,

    /// Disable the automatic 403-driven header/path mutation engine
    #[arg(long)]
    pub no_mitigate: bool,

    /// Exclude the method-override family (X-HTTP-Method-Override et al.)
    /// from the mutation escalation ladder
    #[arg(long)]
    pub no_method_override: bool,

    /// Always apply mutation engine regardless of 403 rate
    #[arg(long)]
    pub mitigate_always: bool,

    /// 403 ratio (0-1) above which the mutation engine activates
    #[arg(long, default_value_t = 0.05)]
    pub mitigate_threshold: f64,

    /// Randomize payload bytes per request (payload entropy)
    #[arg(long)]
    pub entropy: bool,

    /// WebSocket mode configuration: hold[:churn][:send][:size]
    /// e.g. --ws "1000:50:200:64"
    #[arg(long)]
    pub ws: Option<String>,

    /// Force TUI even when stdout is not a TTY
    #[arg(long)]
    pub tui: bool,

    /// Disable TUI (headless; periodic progress to stderr)
    #[arg(long)]
    pub no_tui: bool,

    /// Serve local web dashboard on address, e.g. --web 127.0.0.1:9600
    #[arg(long, value_name = "ADDR")]
    pub web: Option<String>,

    /// Emit final report as JSON (also written when --json-file given)
    #[arg(long)]
    pub json: bool,

    /// Write final JSON report to file
    #[arg(long, value_name = "PATH")]
    pub json_file: Option<String>,

    /// Trace log level (off|error|warn|info|debug|trace)
    #[arg(short = 'v', long, default_value = "warn")]
    pub log_level: String,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Auto,
    H1,
    H2,
    H3,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fidelity {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Opera,
    Okhttp,
    Random,
    None,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyKind {
    Fixed,
    Knee,
    Pulse,
    Brownout,
    Manual,
}

#[derive(Debug, Clone)]
pub struct WsMode {
    pub hold: u64,
    pub churn_per_s: f64,
    pub send_per_s: f64,
    pub size: usize,
}

impl std::str::FromStr for WsMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(':');
        let hold_s = parts.next().ok_or("ws: missing hold")?;
        let churn_s = parts.next().unwrap_or("");
        let send_s = parts.next().unwrap_or("");
        let size_s = parts.next().unwrap_or("");
        let hold: u64 = hold_s.trim().parse::<u64>().map_err(|e| e.to_string())?;
        let churn_per_s = if churn_s.is_empty() {
            0.0
        } else {
            churn_s.trim().parse::<f64>().map_err(|e| e.to_string())?
        };
        let send_per_s = if send_s.is_empty() {
            0.0
        } else {
            send_s.trim().parse::<f64>().map_err(|e| e.to_string())?
        };
        let size = if size_s.is_empty() {
            64.0f64
        } else {
            size_s.trim().parse::<f64>().map_err(|e| e.to_string())?
        } as usize;
        let size = size.clamp(1, 64 * 1024);
        if hold == 0 {
            return Err("ws hold must be > 0".into());
        }
        Ok(WsMode {
            hold,
            churn_per_s,
            send_per_s,
            size,
        })
    }
}

fn default_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().max(1))
        .unwrap_or(1)
}

/// Fully resolved run-time configuration (post-validation).
#[derive(Debug, Clone)]
pub struct Config {
    pub target: String,
    pub method: String,
    pub bind: Option<std::net::IpAddr>,
    pub requests: Option<u64>,
    pub duration: Option<Duration>,
    pub concurrency: usize,
    pub strategy: StrategyKind,
    pub rate: Option<f64>,
    pub poisson: bool,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub entropy: bool,
    pub http_version: HttpVersion,
    pub engine: EngineKind,
    pub tls_verify: bool,
    pub fidelity: Fidelity,
    pub proxy: Option<String>,
    pub timeout: Option<Duration>,
    pub connect_timeout: Duration,
    pub aimd: AimdCfg,
    pub pulse: PulseCfg,
    pub brownout_pct: f64,
    pub mitigate: MitigateCfg,
    pub ws: Option<WsMode>,
    pub tui: bool,
    pub web: Option<SocketAddr>,
    pub json: bool,
    pub json_file: Option<String>,
    pub log_level: String,
}

#[derive(Debug, Clone, Copy)]
pub struct AimdCfg {
    pub alpha: f64,
    pub beta: f64,
    pub delta: f64,
    pub min_rate: f64,
    pub max_rate: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct PulseCfg {
    pub period: f64,
    pub duty: f64,
    pub hi: f64,
    pub lo: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    Wreq,
    H3,
}

#[derive(Debug, Clone, Copy)]
pub struct MitigateCfg {
    pub enabled: bool,
    pub always: bool,
    pub threshold: f64,
    pub method_override: bool,
}

impl CliArgs {
    pub fn into_config(self) -> Result<Config, String> {
        let duration = if self.duration <= 0.0 {
            None
        } else {
            Some(Duration::from_secs_f64(self.duration))
        };
        let requests = if self.requests == 0 {
            None
        } else {
            Some(self.requests)
        };
        let http_version = self.http_version;
        let engine = match http_version {
            HttpVersion::H3 => EngineKind::H3,
            _ => EngineKind::Wreq,
        };
        let strategy = self.strategy.unwrap_or(if self.rate.is_some() {
            StrategyKind::Fixed
        } else {
            StrategyKind::Knee
        });
        let rate = self.rate.map(|r| r as f64);

        let mut headers: Vec<(String, String)> = Vec::new();
        for raw in &self.headers {
            let (k, v) = raw
                .split_once(':')
                .ok_or_else(|| format!("invalid header (want 'Key: Value'): {raw}"))?;
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
        if let Some(ct) = &self.content_type {
            headers.push(("Content-Type".into(), ct.clone()));
        }

        let body = match (&self.body, &self.body_file) {
            (Some(_), Some(_)) => return Err("use --body or --body-file, not both".into()),
            (Some(b), None) => Some(b.clone().into_bytes()),
            (None, Some(f)) => Some(std::fs::read(f).map_err(|e| format!("body file: {e}"))?),
            (None, None) => None,
        };

        let web = self.parse_web()?;
        let timeout = if self.timeout <= 0.0 {
            None
        } else {
            Some(Duration::from_secs_f64(self.timeout))
        };

        let tui = if self.no_tui {
            false
        } else if self.tui {
            true
        } else {
            std::io::IsTerminal::is_terminal(&std::io::stdout())
        };

        if self.ws.is_some() && http_version == HttpVersion::H3 {
            return Err("WebSocket mode is not available over HTTP/3 (use wreq H1/H2)".into());
        }

        Ok(Config {
            target: self.target.clone(),
            method: self.method.clone(),
            bind: self.bind,
            requests,
            duration,
            concurrency: self.concurrency.max(1),
            strategy,
            rate,
            poisson: self.poisson,
            headers,
            body,
            entropy: self.entropy,
            http_version,
            engine,
            tls_verify: self.tls_verify,
            fidelity: self.fidelity,
            proxy: self.proxy.clone(),
            timeout,
            connect_timeout: Duration::from_secs_f64(self.connect_timeout.max(0.1)),
            aimd: AimdCfg {
                alpha: self.aimd_alpha.max(0.001),
                beta: self.aimd_beta.clamp(0.01, 0.999),
                delta: self.aimd_delta.max(0.001),
                min_rate: self.aimd_min_rate.max(1.0),
                max_rate: self.aimd_max_rate.max(10.0),
            },
            pulse: PulseCfg {
                period: self.pulse_period.max(0.5),
                duty: self.pulse_duty.clamp(0.01, 0.99),
                hi: self.pulse_hi.max(1.0),
                lo: self.pulse_lo.max(1.0),
            },
            brownout_pct: self.brownout_pct.clamp(0.01, 1.0),
            mitigate: MitigateCfg {
                enabled: !self.no_mitigate,
                always: self.mitigate_always,
                threshold: self.mitigate_threshold.clamp(0.0, 1.0),
                method_override: !self.no_method_override,
            },
            ws: self.ws.clone().map(|s| s.parse()).transpose()?,
            tui,
            web,
            json: self.json,
            json_file: self.json_file.clone(),
            log_level: self.log_level.clone(),
        })
    }

    fn parse_web(&self) -> Result<Option<SocketAddr>, String> {
        match &self.web {
            None => Ok(None),
            Some(s) => {
                let s = if s.starts_with(':') {
                    format!("127.0.0.1{s}")
                } else {
                    s.to_string()
                };
                s.parse::<SocketAddr>()
                    .map(Some)
                    .map_err(|e| format!("bad --web addr: {e}"))
            }
        }
    }
}
