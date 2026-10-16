//! Swarm distribution: coordinator + node fleet over e2b (or local fake).

pub mod coordinator;
pub mod ingest;
pub mod node;
pub mod provider;
pub mod provision;

/// Convenience constructor used by main for provider selection.
pub fn provider_cfg(p: crate::config::SwarmProvider, template: &str) -> provider::ProviderCfg {
    match p {
        crate::config::SwarmProvider::E2b => {
            let template = std::env::var("K2_TEMPLATE").unwrap_or_else(|_| template.to_string());
            provider::ProviderCfg::E2b {
                template,
                region: None,
            }
        }
        crate::config::SwarmProvider::Fake => provider::ProviderCfg::Fake,
    }
}
