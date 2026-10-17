//! Request materialization: URL templating, mutation application, entropy.

use std::sync::Arc;

use crate::config::{Config, Fidelity};
use crate::controller::mutation::{MitTag, MutationState};
use crate::engine::urltemplate::{UrlTemplate, split_origin};
use crate::error::{K2Error, K2Result};
use crate::tls::fingerprints;

/// Fully materialized request handed to a worker.
#[derive(Debug, Clone)]
pub struct RequestSpec {
    pub seq: u64,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub fidelity: Fidelity,
    /// Per-request source IP for AnyIP rotation (None = use the client's
    /// configured local address).
    pub bind: Option<std::net::IpAddr>,
    /// Mitigation tags actually attached to THIS request (for tool feedback).
    pub mitigation_used: Vec<crate::controller::mutation::MitTag>,
}

/// Builds per-request `RequestSpec`s from the campaign config.
pub struct Materializer {
    method: String,
    origin: String,
    suffix_template: UrlTemplate,
    base_headers: Vec<(String, String)>,
    base_body: Option<Vec<u8>>,
    pub fidelity: Fidelity,
    entropy: bool,
    mutation: Arc<MutationState>,
    bind_net: Option<crate::config::BindNet>,
}

impl Materializer {
    pub fn from_config(cfg: &Config, mutation: Arc<MutationState>) -> K2Result<Self> {
        let (origin, suffix) = split_origin(&cfg.target);
        let suffix_template = UrlTemplate::parse(&suffix).map_err(K2Error::Config)?;
        Ok(Self {
            method: cfg.method.clone(),
            origin,
            suffix_template,
            base_headers: cfg.headers.clone(),
            base_body: cfg.body.clone(),
            fidelity: cfg.fidelity,
            entropy: cfg.entropy,
            mutation,
            bind_net: cfg.bind_net.clone(),
        })
    }

    /// Materialize one request: expand charclasses, apply mutation level,
    /// randomize entropy payloads. Deterministic-random per `seq`.
    pub fn materialize(&self, seq: u64) -> RequestSpec {
        let expanded = self.suffix_template.expand();
        let path_q = self.mutation.mutate_path(&expanded);
        let url = format!("{}{}", self.origin, path_q);

        let mut headers = self.base_headers.clone();
        let mut mitigation_used: Vec<MitTag> = Vec::new();
        if self.mutation.level() >= 1 {
            let tag = self.mutation.mitigation_header();
            headers.push(tag.header());
            if tag.dup {
                // raw-dupe: the same header twice in one request
                headers.push(tag.header());
            }
            mitigation_used.push(tag);
        }
        if self.mutation.level() >= 3 {
            // Method-override family (name × method combos) rides on top.
            let tag = self.mutation.method_override_header();
            headers.push(tag.header());
            mitigation_used.push(tag);
        }

        let body = self.base_body.as_ref().map(|b| {
            if self.entropy {
                let mut b = b.clone();
                for byte in b.iter_mut() {
                    *byte = rand::random();
                }
                b
            } else {
                b.clone()
            }
        });

        RequestSpec {
            seq,
            method: self.method.clone(),
            url,
            headers,
            body,
            fidelity: self.fidelity,
            mitigation_used,
            bind: self.bind_net.as_ref().map(|n| n.pick(seq)),
        }
    }
}

/// Resolve + validate that a URL is syntactically sane before a run begins
/// (cheap guard so campaigns don't fail one request in).
pub fn validate_target(cfg: &Config) -> K2Result<()> {
    let t = &cfg.target;
    let has_scheme = t.starts_with("http://")
        || t.starts_with("https://")
        || t.starts_with("ws://")
        || t.starts_with("wss://");
    if !has_scheme {
        return Err(K2Error::Config(format!("target must include scheme: {t}")));
    }
    let (origin, suffix) = split_origin(t);
    if origin.is_empty() {
        return Err(K2Error::Config("target missing authority".into()));
    }
    let _ = UrlTemplate::parse(&suffix).map_err(K2Error::Config)?;
    let _ = fingerprints::describe(cfg.fidelity);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MitigateCfg;

    fn cfg(target: &str, body: Option<&str>, entropy: bool) -> Config {
        use clap::Parser as _;
        let args =
            crate::config::CliArgs::try_parse_from(["k2", "-d", "5", "--rate", "10", target])
                .unwrap();
        let mut c = args.into_config().unwrap();
        c.target = target.to_string();
        c.body = body.map(|b| b.as_bytes().to_vec());
        c.entropy = entropy;
        c
    }

    fn cfg_with_bind_net(target: &str, cidr: &str) -> Config {
        use clap::Parser as _;
        let args = crate::config::CliArgs::try_parse_from([
            "k2",
            "-d",
            "5",
            "--rate",
            "10",
            "--bind-net",
            cidr,
            target,
        ])
        .unwrap();
        let mut c = args.into_config().unwrap();
        c.target = target.to_string();
        c
    }

    #[test]
    fn materializes_templates() {
        let c = cfg("https://t.local/api/[a-c]?q=[1-2]", Some("{}"), false);
        let m = Materializer::from_config(
            &c,
            Arc::new(MutationState::new(MitigateCfg {
                enabled: false,
                always: false,
                threshold: 1.0,
                method_override: false,
            })),
        )
        .unwrap();
        for seq in 0..8 {
            let s = m.materialize(seq);
            assert!(s.url.starts_with("https://t.local/api/"));
            let q = s.url.split('?').nth(1).unwrap();
            let payload = q.strip_prefix("q=").unwrap();
            assert!(
                payload.as_bytes().iter().all(|b| (b'1'..=b'2').contains(b)),
                "q: {q}"
            );
            assert_eq!(s.body.as_ref().unwrap().as_slice(), b"{}");
        }
    }

    #[test]
    fn entropy_randomizes_body() {
        let c = cfg("https://t.local/", Some("AAAA"), true);
        let m = Materializer::from_config(
            &c,
            Arc::new(MutationState::new(MitigateCfg {
                enabled: false,
                always: false,
                threshold: 1.0,
                method_override: false,
            })),
        )
        .unwrap();
        let mut all_same = true;
        let first = m.materialize(0).body.unwrap();
        for seq in 1..16 {
            let b = m.materialize(seq).body.unwrap();
            if b != first {
                all_same = false;
            }
        }
        assert!(!all_same, "entropy must vary payloads");
    }

    #[test]
    fn bind_net_rotates_source_ip_per_request() {
        let c = cfg_with_bind_net("https://t.local/", "2001:db8::/64");
        let m = Materializer::from_config(
            &c,
            Arc::new(MutationState::new(MitigateCfg {
                enabled: false,
                always: false,
                threshold: 1.0,
                method_override: false,
            })),
        )
        .unwrap();
        let mut seen = std::collections::HashSet::new();
        for seq in 0..64u64 {
            let s = m.materialize(seq);
            let ip = s.bind.expect("bind-net must set a per-request source IP");
            assert!(
                c.bind_net.as_ref().unwrap().net.contains(&ip),
                "picked {ip} outside subnet"
            );
            seen.insert(ip);
        }
        assert!(
            seen.len() > 1,
            "bind-net must rotate source IPs across requests"
        );
        // Deterministic: same seq always yields the same IP.
        assert_eq!(m.materialize(3).bind, m.materialize(3).bind);
    }

    #[test]
    fn validates_urls() {
        let mut c = cfg("https://t.local/path", None, false);
        assert!(validate_target(&c).is_ok());
        c.target = "t.local/path".into();
        assert!(validate_target(&c).is_err());
    }

    #[test]
    fn mutation_headers_applied_uplevel() {
        let c = cfg("https://t.local/", None, false);
        let st = Arc::new(MutationState::new(MitigateCfg {
            enabled: true,
            always: true,
            threshold: 1.0,
            method_override: true,
        }));
        let m = Materializer::from_config(&c, st).unwrap();
        let s = m.materialize(1);
        assert!(
            s.headers
                .iter()
                .any(|(k, _)| k.starts_with("X-") || k.starts_with("CF-") || k.contains("IP"))
        );
    }
}
