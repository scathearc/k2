//! Core execution engine & workers.

pub mod client;
pub mod drain;
pub mod h1;
pub mod h2;
pub mod h3;
pub mod pool;
pub mod request;
pub mod scheduler;
pub mod socks5;
pub mod urltemplate;
pub mod ws;

use std::sync::Arc;
use std::time::Instant;

use crate::config::Config;
use crate::controller::mutation::MutationState;
use crate::engine::request::{Materializer, RequestSpec};

/// Work selection produced by the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    /// One HTTP request cycle (open or pooled connection)
    HttpReq,
    /// Open a persistent WebSocket connection (holds)
    WsOpen,
    /// Send one message into the held WS population
    WsSend,
    /// Close one held WS connection (churn)
    WsClose,
}

/// Fully materialized unit of work.
#[derive(Debug, Clone)]
pub struct Intent {
    pub seq: u64,
    pub intended_send: Instant,
    pub spec: RequestSpec,
    pub work: Work,
}

/// Materializer + mutation front shared by scheduler/workers.
pub struct Front {
    pub materializer: Arc<Materializer>,
    pub mutation: Arc<MutationState>,
}

impl Front {
    pub fn new(cfg: &Config) -> crate::error::K2Result<Self> {
        let mutation = Arc::new(MutationState::new(cfg.mitigate));
        Ok(Self {
            materializer: Arc::new(Materializer::from_config(cfg, mutation.clone())?),
            mutation,
        })
    }
}
