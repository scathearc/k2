//! Swarm providers: how a fleet of k2 nodes comes into existence and dies.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::error::{K2Error, K2Result};

/// One reachable k2 node.
#[derive(Debug, Clone)]
pub struct NodeEndpoint {
    pub id: u64,
    /// Base URL of the node control surface (node-server).
    pub base: String,
}

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Provider: Send + Sync {
    /// Spawn `n` nodes with the given sandbox TTL (seconds).
    fn spawn_fleet(&self, n: u64, ttl_s: u64) -> BoxFut<'_, K2Result<Vec<NodeEndpoint>>>;
    /// Kill the fleet (best-effort; failures are logged, not fatal).
    fn kill_fleet<'a>(&'a self, nodes: &'a [NodeEndpoint]) -> BoxFut<'a, ()>;
}

#[derive(Debug, Clone)]
pub enum ProviderCfg {
    /// e2b Firecracker sandboxes. `template` must be provisioned once via
    /// `k2 swarm provision` (bakes the k2 binary + node start-command).
    E2b {
        template: String,
        region: Option<String>,
    },
    /// Local loopback child processes of this same binary (tests / no-cloud).
    Fake,
}

/// The node-server port every fleet node listens on (public sandbox URL maps it).
pub const NODE_PORT: u16 = 9601;

pub fn build(cfg: ProviderCfg) -> Box<dyn Provider> {
    match cfg {
        ProviderCfg::Fake => Box::new(FakeProvider),
        ProviderCfg::E2b { template, region } => Box::new(E2bProvider {
            api: std::env::var("E2B_DOMAIN")
                .map(|d| format!("https://api.{d}"))
                .unwrap_or_else(|_| "https://api.e2b.app".into()),
            key: std::env::var("E2B_API_KEY").unwrap_or_default(),
            template,
            region,
        }),
    }
}

// ---------------------------------------------------------------------------
// e2b (REST v2)
// ---------------------------------------------------------------------------

struct E2bProvider {
    api: String,
    key: String,
    template: String,
    #[allow(dead_code)] // reserved for multi-region fleets
    region: Option<String>,
}

impl E2bProvider {
    fn client(&self) -> wreq::Client {
        wreq::Client::builder()
            .timeout(Duration::from_secs(30))
            .tls_cert_verification(true)
            .build()
            .expect("e2b client build")
    }

    fn auth(&self) -> K2Result<()> {
        if self.key.is_empty() {
            return Err(K2Error::Config("E2B_API_KEY is not set".into()));
        }
        Ok(())
    }

    /// `https://{port}-{sandboxId}.{domain}` — the SDK getHost() mapping.
    fn node_url(&self, domain: &str, sandbox_id: &str) -> String {
        format!("https://{NODE_PORT}-{sandbox_id}.{domain}")
    }

    async fn create_one(&self, id: u64, ttl_s: u64) -> K2Result<NodeEndpoint> {
        self.auth()?;
        let client = self.client();
        let body = serde_json::json!({
            "templateID": self.template,
            "timeout": ttl_s.max(60),
            "envVars": { "K2_NODE_ID": id.to_string() },
            "metadata": { "k2": "node", "k2_node_id": id.to_string() },
        });
        let resp = client
            .post(format!("{}/v2/sandboxes", self.api))
            .header("X-API-Key", self.key.clone())
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| K2Error::Engine(format!("e2b create: {e}")))?;

        let status = resp.status().as_u16();
        if status != 201 {
            let txt = resp.text().await.unwrap_or_default();
            let ttl = txt.contains("capacity") || txt.contains("sandbox_capacity_unavailable");
            let _ = (ttl, status);
            return Err(K2Error::Proxy(format!("e2b create ({status}): {txt}")));
        }
        let txt = resp.text().await.unwrap_or_default();
        let v: serde_json::Value = serde_json::from_str(&txt)
            .map_err(|e| K2Error::Engine(format!("e2b create json: {e}")))?;
        let sandbox_id = v
            .get("sandboxID")
            .and_then(|s| s.as_str())
            .ok_or_else(|| K2Error::Engine("e2b create: no sandboxID".into()))?
            .to_string();
        let domain = v
            .get("domain")
            .and_then(|s| s.as_str())
            .unwrap_or("e2b.app")
            .to_string();
        Ok(NodeEndpoint {
            id,
            base: self.node_url(&domain, &sandbox_id),
        })
    }
}

impl Provider for E2bProvider {
    fn spawn_fleet<'a>(&'a self, n: u64, ttl_s: u64) -> BoxFut<'a, K2Result<Vec<NodeEndpoint>>> {
        Box::pin(async move {
            // Parallel boot: placement is server-side; quota errors surface
            // here (sandbox_capacity_unavailable) with the count that made it.
            let futs: Vec<_> = (0..n).map(|i| self.create_one(i, ttl_s)).collect();
            let results = futures::future::join_all(futs).await;
            let mut nodes = Vec::new();
            let mut errs = Vec::new();
            for r in results {
                match r {
                    Ok(n_) => nodes.push(n_),
                    Err(e) => errs.push(e.to_string()),
                }
            }
            if nodes.is_empty() {
                return Err(K2Error::Proxy(format!(
                    "e2b fleet failed: {}",
                    errs.join("; ")
                )));
            }
            if !errs.is_empty() {
                tracing::warn!(
                    "e2b: {}/{} nodes booted; failures: {}",
                    nodes.len(),
                    n,
                    errs.join("; ")
                );
            }
            Ok(nodes)
        })
    }

    fn kill_fleet<'a>(&'a self, nodes: &'a [NodeEndpoint]) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let client = self.client();
            for n in nodes {
                let sandbox = sandbox_id_from(&n.base);
                let Some(sandbox) = sandbox else { continue };
                let _ = client
                    .delete(format!("{}/v2/sandboxes/{sandbox}", self.api))
                    .header("X-API-Key", self.key.clone())
                    .send()
                    .await;
            }
        })
    }
}

/// Extracts the sandbox id from a `https://{port}-{id}.{domain}` node URL.
fn sandbox_id_from(base: &str) -> Option<String> {
    let host = base
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(base)
        .split('/')
        .next()?;
    let rest = host.split_once('-').map(|(_, r)| r)?;
    Some(rest.split('.').next()?.to_string())
}

// ---------------------------------------------------------------------------
// fake (local child processes — tests and no-cloud runs)
// ---------------------------------------------------------------------------

struct FakeProvider;

impl Provider for FakeProvider {
    fn spawn_fleet<'a>(&'a self, n: u64, _ttl_s: u64) -> BoxFut<'a, K2Result<Vec<NodeEndpoint>>> {
        Box::pin(async move {
            // In-process node servers on loopback ports (hermetic for tests;
            // child-process spawning would launch the test-runner binary).
            let mut nodes = Vec::new();
            for i in 0..n {
                let port = NODE_PORT + i as u16 + 39;
                tokio::spawn(async move {
                    if let Err(e) = crate::swarm::node::serve(port).await {
                        eprintln!("fake node on {port}: {e}");
                    }
                });
                nodes.push(NodeEndpoint {
                    id: i,
                    base: format!("http://127.0.0.1:{port}"),
                });
            }
            Ok(nodes)
        })
    }

    fn kill_fleet<'a>(&'a self, _nodes: &'a [NodeEndpoint]) -> BoxFut<'a, ()> {
        // Nodes are in-process; drain happens over HTTP; nothing to kill.
        Box::pin(async move {})
    }
}

/// Sandbox-id parse is load-bearing for kill; keep it unit-tested.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sandbox_id_from_public_url() {
        assert_eq!(
            sandbox_id_from("https://9601-sbx-abc123.e2b.app").as_deref(),
            Some("sbx-abc123")
        );
        assert_eq!(sandbox_id_from("http://127.0.0.1:9601"), None);
    }
}
