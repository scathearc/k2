//! Swarm coordinator: owns the closed loop over merged fleet telemetry.
//!
//! Topology: the coordinator DIALS each node's public sandbox URL (pull
//! snapshots / push rates) — no NAT problem, no inbound rules on the operator
//! machine. The controller here runs exactly the same strategy state machine
//! as a local run, just fed by merged windows and commanding rate/N per node.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::config::Config;
use crate::controller::Controller;
use crate::swarm::ingest::{IngestPayload, MergeStore};
use crate::swarm::provider::ProviderCfg;
use crate::telemetry::histogram::HdrConfig;

pub struct SwarmResult {
    pub report: crate::report::RunReport,
    pub interrupted: bool,
    pub nodes: usize,
}

/// Run a distributed campaign across `n` nodes.
pub async fn run_swarm(
    cfg: Config,
    n: u64,
    provider_cfg: ProviderCfg,
    ttl_s: u64,
    mut cancel: impl std::future::Future<Output = ()> + Unpin + Send,
) -> crate::error::K2Result<SwarmResult> {
    crate::engine::request::validate_target(&cfg)?;

    eprintln!(
        "K2 swarm: booting {n} node{} via provider ({})…",
        if n == 1 { "" } else { "s" },
        match provider_cfg {
            ProviderCfg::E2b { .. } => "e2b",
            ProviderCfg::Fake => "fake",
        }
    );
    let provider = crate::swarm::provider::build(provider_cfg);
    let nodes = provider.spawn_fleet(n, ttl_s).await?;

    // Health wait: every node's control surface must answer before configure.
    let client = wreq::Client::builder()
        .timeout(Duration::from_secs(5))
        .tls_cert_verification(true)
        .build()
        .map_err(|e| crate::error::K2Error::Engine(format!("swarm client: {e}")))?;
    let deadline = Instant::now() + Duration::from_secs(180);
    for node in &nodes {
        loop {
            let ok = client
                .get(format!("{}/health", node.base))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if ok {
                break;
            }
            if Instant::now() > deadline {
                return Err(crate::error::K2Error::Engine(format!(
                    "node {} ({}) never became healthy",
                    node.id, node.base
                )));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    eprintln!("K2 swarm: {} node(s) healthy; configuring…", nodes.len());

    // Per-node campaign config: requests split evenly, TUI/web never on nodes.
    let mut node_cfgs = Vec::with_capacity(nodes.len());
    for node in &nodes {
        let mut c = cfg.clone();
        c.tui = false;
        c.web = None;
        c.json_file = None;
        if let Some(req) = cfg.requests {
            c.requests = Some(req.div_ceil(nodes.len() as u64));
        }
        node_cfgs.push(c.clone());
        let body = serde_json::json!({ "node_id": node.id, "config": c });
        let resp = client
            .post(format!("{}/configure", node.base))
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&body).expect("config serialize"))
            .send()
            .await
            .map_err(|e| {
                crate::error::K2Error::Engine(format!("configure node {}: {e}", node.id))
            })?;
        if !resp.status().is_success() {
            return Err(crate::error::K2Error::Engine(format!(
                "configure node {}: {}",
                node.id,
                resp.status()
            )));
        }
    }
    eprintln!(
        "K2 swarm: nodes configured; campaign running (status-first signal governs the fleet)"
    );

    // Merge store + controller, driven at the same 100ms cadence as local runs.
    let lat_cfg = HdrConfig::new(crate::telemetry::LAT_MIN_NS, crate::telemetry::LAT_MAX_NS);
    let merge = Arc::new(MergeStore::new(lat_cfg));
    let (rate_tx, _rate_rx) = watch::channel(cfg.rate.unwrap_or(8.0));
    let (stop_tx, stop_rx) = watch::channel(false);
    let (control_tx, control_rx) = tokio::sync::mpsc::unbounded_channel();
    let entropy = Arc::new(std::sync::atomic::AtomicBool::new(cfg.entropy));

    // Display bus: a Telemetry fed with merged fleet data each tick, so the
    // stock TUI/web surfaces render the SWARM AGGREGATE unchanged. Neither
    // surface runs on nodes — the coordinator owns them.
    let display = Arc::new(crate::telemetry::Telemetry::new());
    display.set_fleet_nodes(nodes.len() as u32);
    display.set_strategy_label(format!("swarm×{} booting", nodes.len()));
    let web_task = cfg.web.map(|addr| {
        let display = display.clone();
        let control = control_tx.clone();
        let stop = stop_rx.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::ui::web::serve(addr, display, control, stop).await {
                tracing::error!("web dashboard exited: {e}");
            }
        })
    });
    let tui_task = if cfg.tui {
        let display = display.clone();
        let control = control_tx.clone();
        let stop = stop_rx.clone();
        Some(tokio::spawn(async move {
            crate::ui::tui::run_tui(display, control, stop).await
        }))
    } else {
        None
    };

    // Controller mutation state: coordinator-side mirror (403 reactions are
    // merged from node data via window s403 counts).
    let mutation = Arc::new(crate::controller::mutation::MutationState::new(
        cfg.mitigate,
    ));
    let mut controller = Controller::new(&cfg, control_rx, entropy, mutation.clone());
    let commanded = Arc::new(AtomicU64::new(0));

    // Poller: pull snapshots from every node (fleet round trip every 500ms),
    // pushing the current commanded rate as a side effect.
    let poll_task = {
        let merge = merge.clone();
        let client = client.clone();
        let nodes = nodes.clone();
        let commanded = commanded.clone();
        let stop = stop_rx.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(500));
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            iv.tick().await;
            while !*stop.borrow() {
                iv.tick().await;
                if *stop.borrow() {
                    break;
                }
                let rate = commanded.load(Ordering::Relaxed) as f64 / nodes.len().max(1) as f64;
                let futs: Vec<_> = nodes
                    .iter()
                    .map(|n| {
                        let client = &client;
                        async move {
                            let snap = match client.get(format!("{}/snapshot", n.base)).send().await
                            {
                                Ok(r) => match r.text().await {
                                    Ok(t) => serde_json::from_str::<Option<IngestPayload>>(&t)
                                        .ok()
                                        .flatten(),
                                    Err(_) => None,
                                },
                                Err(_) => None,
                            };
                            let _ = client
                                .post(format!("{}/rate", n.base))
                                .header("Content-Type", "application/json")
                                .body(serde_json::json!({ "rate": rate }).to_string())
                                .send()
                                .await;
                            snap
                        }
                    })
                    .collect();
                for snap in futures::future::join_all(futs).await.into_iter().flatten() {
                    merge.update(snap);
                }
            }
        })
    };

    // Controller heartbeat over the merged window (inline: the controller
    // stays in scope for the final strategy label).
    let mut interrupted = false;
    let started = Instant::now();
    let mut last_drain = started;
    let mut iv = tokio::time::interval(Duration::from_millis(crate::telemetry::TICK_MS));
    iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    iv.tick().await;
    loop {
        tokio::select! {
            _ = &mut cancel => { interrupted = true; break; }
            _ = iv.tick() => {
                if *stop_rx.borrow() || merge.all_done() {
                    break;
                }
                if let Some(d) = cfg.duration
                    && started.elapsed() >= d + Duration::from_secs(15)
                {
                    break;
                }
                if controller.poll_quit() {
                    break;
                }
                let (window, win_lat) = merge.drain_window();
                let window_ms = last_drain.elapsed().as_millis() as u64;
                last_drain = Instant::now();
                if std::env::var("K2_LOG_SWARM").is_ok() {
                    eprintln!(
                        "k2-swarm: t={}ms window count={} err={} ms={window_ms}",
                        started.elapsed().as_millis(),
                        window.count,
                        window.errors
                    );
                }
                let window_agg = crate::telemetry::histogram::Agg {
                    cfg: lat_cfg,
                    total: win_lat.iter().sum(),
                    counts: win_lat.clone(),
                };
                let window_p99 = window_agg.quantile(0.99).unwrap_or(0) as f64;
                let attempts = window.count + window.errors;
                let status_ratio = if attempts > 0 {
                    (window.bad_status + window.errors) as f64 / attempts as f64
                } else {
                    0.0
                };
                let elapsed_ms = started.elapsed().as_millis() as u64;
                // RPS over the window's TRUE span — poll deltas arrive in
                // ~500ms chunks; assuming 100ms windows inflates rps ~5×.
                let actual_rps = if window_ms > 0 {
                    window.count as f64 * 1000.0 / window_ms as f64
                } else {
                    0.0
                };
                let rate = controller.on_tick(elapsed_ms, &window, window_p99, status_ratio, actual_rps);
                commanded.store(rate as u64, Ordering::Relaxed);
                let _ = rate_tx.send(rate);

                // Mirror the merged fleet state into the display bus.
                let md = merge.merged_display();
                display.set_target_rate(rate);
                display.set_strategy_label(format!(
                    "{} · fleet {} node{}",
                    controller.label(),
                    nodes.len(),
                    if nodes.len() == 1 { "" } else { "s" }
                ));
                display.swarm_tick(crate::telemetry::SwarmTick {
                    window,
                    win_lat_buckets: win_lat,
                    cum_lat_counts: md.lat_counts,
                    cum_lag_counts: md.lag_counts,
                    status_map: md.statuses,
                    error_map: md.errors,
                    count_total: md.count_total,
                    dispatched: md.dispatched,
                    in_flight: md.in_flight,
                    bytes_in: md.bytes_in,
                    bytes_out: md.bytes_out,
                    ws_held: md.ws_held,
                    window_ms,
                });
            }
        }
    }

    let _ = stop_tx.send(true);
    let _ = poll_task.await;

    // Graceful drain: ask every node, collect finals, kill the fleet.
    for node in &nodes {
        let _ = client.post(format!("{}/drain", node.base)).send().await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    for node in &nodes {
        if let Ok(r) = client.get(format!("{}/snapshot", node.base)).send().await
            && let Ok(t) = r.text().await
            && let Ok(Some(mut p)) = serde_json::from_str::<Option<IngestPayload>>(&t)
        {
            p.done = true;
            merge.update(p);
        }
    }
    provider.kill_fleet(&nodes).await;

    // Final display frame before the UIs shut down, then join them.
    {
        let md = merge.merged_display();
        let _ = display.swarm_tick(crate::telemetry::SwarmTick {
            window: Default::default(),
            win_lat_buckets: Vec::new(),
            cum_lat_counts: md.lat_counts,
            cum_lag_counts: md.lag_counts,
            status_map: md.statuses,
            error_map: md.errors,
            count_total: md.count_total,
            dispatched: md.dispatched,
            in_flight: md.in_flight,
            bytes_in: md.bytes_in,
            bytes_out: md.bytes_out,
            ws_held: md.ws_held,
            window_ms: crate::telemetry::TICK_MS,
        });
    }
    if let Some(t) = web_task {
        let _ = t.await;
    }
    if let Some(t) = tui_task {
        let _ = t.await;
    }

    let (lat, lag, statuses, errors, count_total, dispatched, bytes_in, bytes_out, ws) =
        merge.merged_final();
    let runtime = started.elapsed();
    let actual_rps = if runtime.as_secs_f64() > 0.0 {
        count_total as f64 / runtime.as_secs_f64()
    } else {
        0.0
    };
    let strategy_label = controller.label();
    let http_version = crate::runtime::http_display(cfg.http_version);

    let report = crate::report::build(
        &cfg.target,
        &format!("{strategy_label} [swarm×{}]", nodes.len()),
        runtime,
        dispatched,
        &(lat, lag),
        statuses,
        errors,
        (bytes_in, bytes_out),
        actual_rps,
        commanded.load(Ordering::Relaxed) as f64,
        ws,
        0,
        crate::tls::fingerprints::describe(cfg.fidelity),
        &http_version,
        cfg.proxy.clone(),
        mutation.level_label(),
    );
    let _ = count_total;

    Ok(SwarmResult {
        report,
        interrupted,
        nodes: nodes.len(),
    })
}
