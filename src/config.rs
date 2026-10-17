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
    #[arg(required_unless_present_any = ["swarm_provision", "node_server"])]
    pub target: Option<String>,

    /// One-time: scaffold + build the k2-node e2b template (needs e2b CLI)
    #[arg(long, value_name = "TEMPLATE")]
    pub swarm_provision: Option<String>,

    /// Node-server mode: wait for coordinator configure/snapshot/rate calls
    #[arg(long, value_name = "PORT")]
    pub node_server: Option<u16>,

    /// Distribute the campaign across N e2b sandboxes (swarm coordinator mode)
    #[arg(long, value_name = "N")]
    pub swarm: Option<u64>,

    /// Swarm provider: e2b | fake (local loopback child nodes)
    #[arg(long, value_enum, default_value_t = SwarmProvider::E2b)]
    pub provider: SwarmProvider,

    /// Provisioned e2b template name (or K2_TEMPLATE env)
    #[arg(long, default_value = "k2-node")]
    pub swarm_template: String,

    /// Fleet node count of the node-server port inside sandboxes
    #[arg(long, default_value_t = 9601)]
    pub swarm_port: u16,

    /// Sandbox TTL seconds (e2b)
    #[arg(long, default_value_t = 3600)]
    pub sandbox_ttl: u64,

    /// Total number of requests to issue (0 = unlimited)
    #[arg(short = 'n', long, default_value_t = 0)]
    pub requests: u64,

    /// Run duration in seconds (0 = until request count or auto budget)
    #[arg(short = 'd', long, default_value_t = 60.0)]
    pub duration: f64,

    /// Worker concurrency floor (number of in-flight workers). In
    /// closed-loop (Knee) mode the pool grows automatically with the
    /// commanded rate — this is the starting floor.
    #[arg(short = 'c', long, default_value_t = default_concurrency())]
    pub concurrency: usize,

    /// Hard ceiling on the auto-scaled worker pool
    #[arg(long, default_value_t = 4096)]
    pub max_workers: usize,

    /// Fixed target requests/second. If omitted, defaults to closed-loop Knee (AIMD) hunting
    #[arg(long)]
    pub rate: Option<u64>,

    /// Local source IP to bind outbound sockets (TCP clients + H3 UDP).
    /// Requires a routable local address (AnyIP setups need CAP_NET_ADMIN).
    #[arg(long, value_name = "IP")]
    pub bind: Option<std::net::IpAddr>,

    /// CIDR subnet to draw a different source IP from for EVERY request
    /// (AnyIP source rotation). e.g. --bind-net 2001:db8::/64. Overrides
    /// --bind when both are set.
    #[arg(long, value_name = "CIDR")]
    pub bind_net: Option<String>,

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

    /// AIMD latency-derivative threshold (relative dLat/dt per second).
    /// Only consulted when --degrade-signal includes latency.
    #[arg(long, default_value_t = 0.35)]
    pub aimd_delta: f64,

    /// Degradation signal the closed loop judges: status (non-2xx+error
    /// ratio — primary, reliable), latency (dLat/dt derivative — a queue-depth
    /// signal, NOT a health signal), or both.
    #[arg(long, value_enum, default_value_t = DegradeSignal::Status)]
    pub degrade_signal: DegradeSignal,

    /// Non-2xx + transport-error ratio (0-1) above which the loop judges the
    /// target degraded. Latency alone never triggers this.
    #[arg(long, default_value_t = 0.02)]
    pub degrade_status_threshold: f64,

    /// Minimum AIMD rate floor (requests/sec)
    #[arg(long, default_value_t = 1.0)]
    pub aimd_min_rate: f64,

    /// Maximum AIMD rate ceiling (requests/sec). Blind knee-hunt runs default
    /// to a conservative 5k ceiling; raise explicitly for capacity tests.
    #[arg(long, default_value_t = 5_000.0)]
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

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpVersion {
    Auto,
    H1,
    H2,
    H3,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
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

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StrategyKind {
    Fixed,
    Knee,
    Pulse,
    Brownout,
    Manual,
}

#[derive(
    ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum DegradeSignal {
    /// Non-2xx status + transport-error ratio (reliable "is it broken")
    #[default]
    Status,
    /// Latency derivative dLat/dt (queue-depth indicator; can mislead)
    Latency,
    /// Either signal trips the loop
    Both,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SwarmProvider {
    /// e2b Firecracker sandboxes (needs E2B_API_KEY + provisioned template)
    #[default]
    E2b,
    /// Local loopback child processes (tests / no-cloud runs)
    Fake,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub target: String,
    pub method: String,
    #[serde(default)]
    pub bind: Option<std::net::IpAddr>,
    #[serde(default)]
    pub bind_net: Option<BindNet>,
    pub requests: Option<u64>,
    pub duration: Option<Duration>,
    pub concurrency: usize,
    pub max_workers: usize,
    pub strategy: StrategyKind,
    pub rate: Option<f64>,
    #[serde(default)]
    pub poisson: bool,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    #[serde(default)]
    pub entropy: bool,
    pub http_version: HttpVersion,
    pub engine: EngineKind,
    pub tls_verify: bool,
    pub fidelity: Fidelity,
    #[serde(default)]
    pub proxy: Option<String>,
    pub timeout: Option<Duration>,
    pub connect_timeout: Duration,
    pub aimd: AimdCfg,
    pub pulse: PulseCfg,
    pub brownout_pct: f64,
    pub mitigate: MitigateCfg,
    #[serde(default)]
    pub ws: Option<WsMode>,
    #[serde(default)]
    pub tui: bool,
    #[serde(default)]
    pub web: Option<SocketAddr>,
    #[serde(default)]
    pub json: bool,
    #[serde(default)]
    pub json_file: Option<String>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "warn".into()
}

/// A CIDR subnet for AnyIP source rotation: every request draws a fresh
/// source address from the subnet, so the target sees a rotating source
/// rather than a single pinned IP.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BindNet {
    pub net: ipnet::IpNet,
}

impl std::fmt::Display for BindNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.net)
    }
}

impl BindNet {
    pub fn parse(s: &str) -> Result<Self, String> {
        let net: ipnet::IpNet = s
            .parse()
            .map_err(|e| format!("invalid --bind-net CIDR {s}: {e}"))?;
        // Only a subnet with a routable host portion can rotate; a /32 or
        // /128 is a single address and would be a no-op rotation.
        if net.prefix_len()
            >= match net {
                ipnet::IpNet::V4(_) => 32,
                ipnet::IpNet::V6(_) => 128,
            }
        {
            return Err(format!(
                "--bind-net {s} has no routable host addresses (use a /64 or smaller)"
            ));
        }
        Ok(Self { net })
    }

    /// Deterministic-random source address for `seq`. Seeded from seq so
    /// retries and re-runs reproduce the same address for a given seq.
    pub fn pick(&self, seq: u64) -> std::net::IpAddr {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        seq.hash(&mut h);
        let n = h.finish() as u128;
        match self.net {
            ipnet::IpNet::V4(net) => {
                let base = u32::from_be_bytes(net.network().octets());
                let host = n % (1u128 << (32 - net.prefix_len()));
                std::net::IpAddr::V4(std::net::Ipv4Addr::from((base as u128 + host) as u32))
            }
            ipnet::IpNet::V6(net) => {
                let base = u128::from_be_bytes(net.network().octets());
                let host = n % (1u128 << (128 - net.prefix_len()));
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(base + host))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct AimdCfg {
    pub alpha: f64,
    pub beta: f64,
    pub delta: f64,
    pub min_rate: f64,
    pub max_rate: f64,
    pub signal: DegradeSignal,
    pub status_threshold: f64,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct PulseCfg {
    pub period: f64,
    pub duty: f64,
    pub hi: f64,
    pub lo: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineKind {
    Wreq,
    H3,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
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
        // Auto budget guard: `-d 0` without `-n` must never run unbounded.
        let requests = match (requests, duration) {
            (None, None) => Some(100_000u64),
            (r, _) => r,
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
            target: self
                .target
                .clone()
                .ok_or_else(|| "missing <TARGET>".to_string())?,
            method: self.method.clone(),
            bind: self.bind,
            bind_net: self.bind_net.as_deref().map(BindNet::parse).transpose()?,
            requests,
            duration,
            concurrency: self.concurrency.max(1),
            max_workers: self.max_workers.max(16),
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
                signal: self.degrade_signal,
                status_threshold: self.degrade_status_threshold.clamp(0.001, 1.0),
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

#[cfg(test)]
mod bind_net_tests {
    use super::*;

    #[test]
    fn pick_rotates_within_subnet() {
        let bn = BindNet::parse("2001:db8::/64").unwrap();
        let mut addrs = std::collections::HashSet::new();
        for seq in 0..200u64 {
            let ip = bn.pick(seq);
            assert!(bn.net.contains(&ip), "picked {ip} outside {bn}");
            addrs.insert(ip);
        }
        assert!(addrs.len() > 1, "bind-net must rotate source IPs");
    }

    #[test]
    fn parse_rejects_full_range() {
        assert!(BindNet::parse("2001:db8::/128").is_err());
        assert!(BindNet::parse("10.0.0.1/32").is_err());
    }

    #[test]
    fn pick_is_deterministic() {
        let bn = BindNet::parse("2001:db8::/64").unwrap();
        assert_eq!(bn.pick(7), bn.pick(7));
        assert_ne!(bn.pick(7), bn.pick(8));
    }

    #[test]
    fn pick_v4_rotates_within_subnet() {
        let bn = BindNet::parse("10.0.0.0/24").unwrap();
        let mut addrs = std::collections::HashSet::new();
        for seq in 0..300u64 {
            let ip = bn.pick(seq);
            assert!(bn.net.contains(&ip), "picked {ip} outside {bn}");
            addrs.insert(ip);
        }
        assert!(addrs.len() > 1, "bind-net must rotate source IPs");
    }
}
