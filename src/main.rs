//! CLI entry point, flag parsing, and mode dispatch:
//! normal run | swarm coordinator | swarm node | template provisioning.

use anyhow::anyhow;
use clap::Parser;

use k2::config::CliArgs;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    init_tracing(&args.log_level);
    eprintln!("{}", k2::AUTHORIZED_USE);

    // Mode 1: one-time template provisioning (e2b).
    if let Some(template) = &args.swarm_provision {
        return k2::swarm::provision::provision(template).await;
    }

    // Mode 2: swarm node (waits for the coordinator to configure it).
    if let Some(port) = args.node_server {
        return k2::swarm::node::serve(port)
            .await
            .map_err(|e| anyhow!("node server: {e}"));
    }

    // Mode 3: swarm coordinator.
    if let Some(n) = args.swarm {
        let cfg = parse_config(&args)?;
        eprintln!(
            "K2 swarm coordinator: {} nodes via {:?}, sandbox TTL {}s",
            n, args.provider, args.sandbox_ttl
        );
        let ctrlc = Box::pin(async {
            let _ = tokio::signal::ctrl_c().await;
        });
        let out = k2::swarm::coordinator::run_swarm(
            cfg,
            n,
            k2::swarm::provider_cfg(args.provider, &args.swarm_template),
            args.sandbox_ttl,
            ctrlc,
        )
        .await?;
        return finish(out.report, out.interrupted, &args);
    }

    // Mode 4: single-node run (the default).
    let cfg = parse_config(&args)?;
    let ctrlc = Box::pin(async {
        let _ = tokio::signal::ctrl_c().await;
    });

    let outcome = k2::run(cfg.clone(), ctrlc).await?;
    finish(outcome.report, outcome.interrupted, &args)
}

fn finish(report: k2::report::RunReport, interrupted: bool, args: &CliArgs) -> anyhow::Result<()> {
    if interrupted {
        eprintln!("k2: interrupted — graceful drain complete");
    }
    let json = report.to_json();
    if args.json {
        println!("{json}");
    } else {
        println!("{}", k2::report::render_text(&report));
    }
    if let Some(path) = &args.json_file {
        std::fs::write(path, json + "\n").map_err(|e| anyhow!("write json report: {e}"))?;
    }
    if report.failure_rate() >= 0.999 {
        eprintln!("k2: all requests failed");
        std::process::exit(3);
    }
    Ok(())
}

fn parse_config(args: &CliArgs) -> anyhow::Result<k2::Config> {
    args.clone()
        .into_config()
        .map_err(|e| anyhow!("config: {e}"))
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
