//! Campaign orchestration: wires scheduler, workers, controller, telemetry
//! bus, and optional UI surfaces into one run, ending with a final report.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use crate::config::{Config, HttpVersion, StrategyKind};
use crate::controller::Controller;
use crate::engine::Front;
use crate::engine::pool::{Engine, spawn_workers};
use crate::engine::scheduler::Scheduler;
use crate::error::K2Result;
use crate::telemetry::{TICK_MS, Telemetry, TickData};
use crate::tls::fingerprints;

/// Public control surface — same messages as TUI hotkeys / web controls.
#[allow(dead_code)]
pub type ControlTx = mpsc::UnboundedSender<crate::controller::ControlMsg>;

pub struct RunOutcome {
    pub report: crate::report::RunReport,
    pub interrupted: bool,
}

/// Entry: run a full campaign, return the report. `cancel` fires the
/// graceful-drain path (SIGINT / TUI `[Q]` / web drain).
pub async fn run(
    cfg: Config,
    mut cancel: impl std::future::Future<Output = ()> + Unpin + Send,
) -> K2Result<RunOutcome> {
    crate::engine::request::validate_target(&cfg)?;
    let cfg = Arc::new(cfg);

    let telemetry = Arc::new(Telemetry::new());
    let start_rate = cfg.rate.unwrap_or(8.0);
    let (rate_tx, rate_rx) = watch::channel(start_rate);
    let (stop_tx, stop_rx) = watch::channel(false);
    let (control_tx, control_rx) = mpsc::unbounded_channel();
    let entropy = Arc::new(std::sync::atomic::AtomicBool::new(cfg.entropy));

    let front = Front::new(&cfg)?;
    let engine =
        Arc::new(Engine::build(&cfg, stop_rx.clone(), Some(front.mutation.clone())).await?);
    let engine_ws = engine.clone();

    let (intents_tx, intents_rx) =
        mpsc::channel::<crate::engine::Intent>((cfg.concurrency * 16).clamp(64, 16384));
    let scheduler = Scheduler {
        cfg: cfg.clone(),
        materializer: front.materializer.clone(),
        intents_tx,
        rate_rx,
        telemetry: telemetry.clone(),
        stop_rx: stop_rx.clone(),
    };
    let workers = spawn_workers(engine.clone(), telemetry.clone(), intents_rx);

    // Optional web dashboard (spawn; never blocks the run).
    let web_task = cfg.web.map(|addr| {
        let telemetry = telemetry.clone();
        let control = control_tx.clone();
        let stop = stop_rx.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::ui::web::serve(addr, telemetry, control, stop).await {
                tracing::error!("web dashboard exited: {e}");
            }
        })
    });

    // Optional TUI dashboard.
    let tui_task = if cfg.tui {
        let telemetry = telemetry.clone();
        let control = control_tx.clone();
        let stop = stop_rx.clone();
        Some(tokio::spawn(async move {
            crate::ui::tui::run_tui(telemetry, control, stop).await
        }))
    } else {
        None
    };

    // 100ms heartbeat: telemetry snapshot → controller tick → rate publish.
    let tick_task = {
        let telemetry = telemetry.clone();
        let stop_rx_t = stop_rx.clone();
        let rate_tx = rate_tx.clone();
        let cfg = cfg.clone();
        let mutation = front.mutation.clone();
        tokio::spawn(async move {
            let mut controller = Controller::new(&cfg, control_rx, entropy, mutation);
            let mut iv = tokio::time::interval(Duration::from_millis(TICK_MS));
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            iv.tick().await; // first tick returns immediately
            while !*stop_rx_t.borrow() {
                iv.tick().await;
                if *stop_rx_t.borrow() {
                    break;
                }
                if controller.poll_quit() {
                    break;
                }
                let td: TickData = telemetry.begin_tick();
                let window_p99 = telemetry.window_p99_of(&td);
                let elapsed_ms = telemetry.started().elapsed().as_millis() as u64;
                let window_rps = (td.window.count as f64) * (1000.0 / TICK_MS as f64);
                let rate = controller.on_tick(elapsed_ms, &td.window, window_p99, window_rps);
                telemetry.set_target_rate(rate);
                telemetry.set_strategy_label(controller.label());
                telemetry.finish_tick(td);
                let _ = rate_tx.send(rate);
            }
        })
    };

    // Drive the scheduler to completion (or cancellation).
    let mut interrupted = false;
    let scheduler_task = tokio::spawn(scheduler.run());
    tokio::select! {
        _ = &mut cancel => {
            interrupted = true;
        }
        done = scheduler_task => {
            let _ = done;
        }
    }

    // Graceful drain: close intents, stop bus + optional surfaces, wait sockets.
    let _ = stop_tx.send(true);
    for w in workers {
        let _ = w.await;
    }
    let _ = tick_task.await;
    if let Some(t) = web_task {
        let _ = t.await;
    }
    if let Some(t) = tui_task {
        let _ = t.await;
    }

    let ws_stats = match (&cfg.ws, engine_ws.ws()) {
        (Some(_), Some(ws)) => Some(ws.drain_all().await),
        _ => None,
    };

    let (agg_lat, agg_lag) = telemetry.aggregate();
    let (statuses, errors, bytes_in, bytes_out, ws_held) = telemetry.cumulative_maps();
    let runtime = telemetry.started().elapsed();
    let actual_rps = if runtime.as_secs_f64() > 0.0 {
        telemetry.count_total() as f64 / runtime.as_secs_f64()
    } else {
        0.0
    };
    let target_rps = telemetry.snapshot().target_rate;
    let strategy_label = strategy_display(&cfg);
    let http_version = http_display(cfg.http_version);

    let report = crate::report::build(
        &cfg.target,
        &strategy_label,
        runtime,
        telemetry.dispatched(),
        &(agg_lat, agg_lag),
        statuses,
        errors,
        (bytes_in, bytes_out),
        actual_rps,
        target_rps,
        ws_stats,
        ws_held,
        fingerprints::describe(cfg.fidelity),
        &http_version,
        cfg.proxy.clone(),
        front.mutation.level_label(),
    );

    Ok(RunOutcome {
        report,
        interrupted,
    })
}

fn strategy_display(cfg: &Config) -> String {
    match cfg.strategy {
        StrategyKind::Fixed => format!("Fixed {:.0} rps", cfg.rate.unwrap_or(0.0)),
        StrategyKind::Knee => "Knee-of-Curve AIMD".to_string(),
        StrategyKind::Pulse => format!("Square-Wave Pulse {:.0}/{:.0}", cfg.pulse.hi, cfg.pulse.lo),
        StrategyKind::Brownout => format!("Brownout {:.0}%", cfg.brownout_pct * 100.0),
        StrategyKind::Manual => "Manual".to_string(),
    }
}

pub fn http_display(v: HttpVersion) -> String {
    match v {
        HttpVersion::Auto => "auto (negotiated)".to_string(),
        HttpVersion::H1 => "http/1.1".to_string(),
        HttpVersion::H2 => "http/2".to_string(),
        HttpVersion::H3 => "http/3".to_string(),
    }
}
