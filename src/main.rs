//! CLI entry point, flag parsing, and execution dispatch.

use anyhow::anyhow;
use clap::Parser;

use k2::config::CliArgs;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    let cfg = match args.into_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };

    init_tracing(&cfg.log_level);
    eprintln!("{}", k2::AUTHORIZED_USE);

    // SIGINT → graceful drain, then report wrap-up.
    let ctrlc = Box::pin(async {
        let _ = tokio::signal::ctrl_c().await;
    });

    let outcome = k2::run(cfg.clone(), ctrlc).await?;

    let report = outcome.report;
    let json = report.to_json();
    if cfg.json {
        println!("{json}");
    } else {
        println!("{}", k2::report::render_text(&report));
    }
    if let Some(path) = &cfg.json_file {
        std::fs::write(path, json + "\n").map_err(|e| anyhow!("write json report: {e}"))?;
    }

    // Non-zero exit when the run couldn't complete meaningfully.
    if report.failure_rate() >= 0.999 {
        eprintln!("k2: all requests failed");
        std::process::exit(3);
    }
    Ok(())
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
