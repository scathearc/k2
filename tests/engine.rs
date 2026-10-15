//! End-to-end engine integration tests against the local harness.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{config, spawn};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_adherence_fixed() {
    let (addr, state, shutdown) = spawn().await;
    let cfg = config(&format!("http://{addr}/"), &["--rate", "200", "-d", "2"]);
    let out = k2::run(cfg, std::future::pending()).await.unwrap();
    let _ = shutdown.send(());
    let r = &out.report;
    let hits = state.hits.load(Ordering::Relaxed);
    // ±15% tolerance for scheduler + runtime slop
    assert!(
        (380..=462).contains(&hits),
        "hits {hits} outside ±15%% of 400; actual_rps {:.1}",
        r.actual_rps
    );
    assert!(r.actual_rps > 150.0, "actual rps {}", r.actual_rps);
    assert!(
        r.statuses.iter().any(|s| s.code == 200),
        "statuses {:?}",
        r.statuses
    );
    assert!(
        r.errors.is_empty(),
        "unexpected transport errors: {:?}",
        r.errors
    );
    assert!(
        r.scheduler_lag_p99_ms < 250.0,
        "scheduler lag {}",
        r.scheduler_lag_p99_ms
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coordinated_omission_anchoring() {
    // /late starts fast (5ms); mid-run we inject 350ms. Because every sample
    // is anchored to intended dispatch time, the aggregate p99 must carry the
    // injected latency instead of being masked by send-time drift. Ample
    // workers (-c 32) keep the open-loop queue from backing up.
    let (addr, state, shutdown) = spawn().await;
    let cfg = config(
        &format!("http://{addr}/late"),
        &["--rate", "50", "-d", "3", "-c", "32"],
    );
    let st = state.clone();
    let bump = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(800)).await;
        st.latency_ms.store(350, Ordering::Relaxed);
    });

    let out = k2::run(cfg, std::future::pending()).await.unwrap();
    bump.abort();
    let _ = shutdown.send(());

    let r = &out.report;
    let p99_ms = r.latency.p99_ms;
    // p99 must reflect the 350ms injected server latency (CO-anchored)…
    assert!(
        p99_ms >= 300.0,
        "p99 {p99_ms}ms did not carry injected latency"
    );
    // …and the mean must be far above the 5ms pre-injection baseline.
    assert!(r.latency.mean_ms >= 80.0, "mean {}ms", r.latency.mean_ms);
    // Every dispatched intent must be accounted for (no silent drops).
    let accounted = r.responses + r.errors.iter().map(|e| e.count).sum::<u64>();
    assert!(
        accounted as f64 >= 0.9 * r.requests_sent as f64,
        "sent {} accounted {accounted}",
        r.requests_sent
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_accounting_and_mutation_trigger() {
    let (addr, state, shutdown) = spawn().await;
    // Hammer 403s for the whole run window.
    state.fail_403_until.store(u64::MAX, Ordering::Relaxed);
    let cfg = config(
        &format!("http://{addr}/storm"),
        &["--rate", "60", "-d", "2", "--mitigate-threshold", "0.02"],
    );
    let out = k2::run(cfg, std::future::pending()).await.unwrap();
    let _ = shutdown.send(());

    let r = &out.report;
    let s403 = r
        .statuses
        .iter()
        .find(|s| s.code == 403)
        .expect("403s recorded");
    assert!(s403.pct > 50.0, "403 pct {}", s403.pct);
    // Mutation engine must have escalated from level 0.
    assert_ne!(r.mutation_active, "none", "mutation engine never escalated");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drain_on_cancel_is_graceful() {
    let (addr, _state, shutdown) = spawn().await;
    let cfg = config(&format!("http://{addr}/"), &["--rate", "100", "-d", "30"]);
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
    let cancel = async move {
        let _ = cancel_rx.await;
    };
    let boxed = Box::pin(cancel);
    let run_task = tokio::spawn(k2::run(cfg, boxed));
    tokio::time::sleep(Duration::from_millis(700)).await;
    let _ = cancel_tx.send(());
    let out = run_task.await.unwrap().unwrap();
    let _ = shutdown.send(());
    assert!(out.interrupted, "run must report interruption");
    assert!(
        out.report.responses > 0,
        "graceful drain lost all responses"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn template_expansion_works_end_to_end() {
    let (addr, state, shutdown) = spawn().await;
    let cfg = config(
        &format!("http://{addr}/?q=[a-b][1-2]"),
        &["--rate", "40", "-d", "1"],
    );
    let out = k2::run(cfg, std::future::pending()).await.unwrap();
    let _ = shutdown.send(());
    assert!(
        out.report.responses > 20,
        "responses {}",
        out.report.responses
    );
    assert!(state.hits.load(Ordering::Relaxed) > 20);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_hold_and_churn() {
    let (addr, _state, shutdown) = spawn().await;
    let cfg = config(
        &format!("ws://{addr}/ws"),
        &["--ws", "8:4:20:64", "--rate", "40", "-d", "2"],
    );
    let out = k2::run(cfg, std::future::pending()).await.unwrap();
    let _ = shutdown.send(());

    let Some(ws) = out.report.ws else {
        panic!("ws stats missing from report");
    };
    assert!(ws.opened >= 8, "opened {}", ws.opened);
    assert!(ws.failed == 0, "failed {}", ws.failed);
    assert!(ws.closed > 0, "closed {}", ws.closed);
    assert!(ws.sent > 0, "sent {}", ws.sent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_strategy_switch_via_control_channel() {
    let (addr, _state, shutdown) = spawn().await;
    // Knee (closed-loop) start; the harness is fast so the knee should climb.
    let cfg = config(&format!("http://{addr}/"), &["-d", "10"]);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let cancel = async move {
        let _ = rx.await;
    };
    let run_task = tokio::spawn(k2::run(cfg, Box::pin(cancel)));

    // Let the closed-loop knee climb for a while, then drain.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let _ = tx.send(());
    let out = run_task.await.unwrap().unwrap();
    let _ = shutdown.send(());
    assert!(out.interrupted, "expected cancel-driven drain");
    assert!(
        out.report.responses > 60,
        "closed-loop run too small: {} (target_rps {:.0})",
        out.report.responses,
        out.report.target_rps
    );
    assert!(out.report.errors.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn report_json_shape() {
    let (addr, _state, shutdown) = spawn().await;
    let cfg = config(
        &format!("http://{addr}/"),
        &["--rate", "50", "-d", "1", "--json"],
    );
    let out = k2::run(cfg, std::future::pending()).await.unwrap();
    let _ = shutdown.send(());
    let j = out.report.to_json();
    let v: serde_json::Value = serde_json::from_str(&j).expect("json parse");
    for key in [
        "target",
        "strategy",
        "responses",
        "latency",
        "statuses",
        "errors",
    ] {
        assert!(v.get(key).is_some(), "missing key {key}");
    }
    assert_eq!(v["coordinated_omission_corrected"], serde_json::json!(true));
}
