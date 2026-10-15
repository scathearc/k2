pub mod config;
pub mod controller;
pub mod engine;
pub mod error;
pub mod report;
pub mod telemetry;
pub mod tls;
pub mod ui;

pub use config::{CliArgs, Config, EngineKind, Fidelity, StrategyKind, WsMode};
pub use report::RunReport;

mod runtime;

pub use runtime::run;

/// Hard banner asserted in `--help` and every run: use only on authorized targets.
pub const AUTHORIZED_USE: &str =
    "K2 is a load testing tool. Use only on targets you are authorized to test.";
