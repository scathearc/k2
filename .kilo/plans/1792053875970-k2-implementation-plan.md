# K2 — Implementation Plan

Source spec: `SPEC.md` (repo root). Authoritative for feature intent; this plan resolves its open forks into buildable decisions.

## 1. Goal

Single statically-linked Rust binary, `k2`, that generates closed-loop HTTP load against authorized targets with: browser-fidelity TLS, coordinated-omission-corrected latency measurement, adaptive closed-loop rate control (AIMD knee-hunting), anti-warmup traffic modulation, residential proxy traversal (incl. SOCKS5 UDP ASSOCIATE for HTTP/3), TUI + web dashboards, and oha-style CLI ergonomics.

## 2. Resolved design decisions

| # | Decision | Resolution |
|---|----------|-----------|
| D1 | Scope | **Single-node only.** Spec §9 distributed swarm (WireGuard, gRPC control channel, SSH/Docker/Nomad/K8s provisioning) is **out of scope**. Leave seams: `TelemetrySink` trait, `ControlPlane` trait. |
| D2 | TLS/engine stack | **Consolidated: `wreq` (BoringSSL 6.0.0-rc) is THE engine for HTTP/1.1, HTTP/2, and WebSocket.** `quinn`+`h3` for HTTP/3 (quinn uses rustls internally; the cert-bypass verifier lives there). Plain `http://` also flows through wreq — one measurement profile, no per-scheme engine forks. |
| D3 | Default identity | **Randomized browser emulation profile per TLS connection** (wreq-util `Emulation`, 100+ presets) as spec demands. `--fidelity <chrome\|firefox\|safari\|ok-http\|random\|none>`; default `random`. Cert verification bypass (**default ON**, spec-mandated CPU saving) via wreq `danger_accept_invalid_certs` + custom TlsSettings; `--tls-verify` restores validation. |
| D4 | UX surfaces | Both TUI (ratatui) and web dashboard (axum + WS). TUI auto-starts when attached to a TTY; headless mode otherwise; `--no-tui` / `--web <addr>` overrides. Headless always ends with text report; `--json` emits machine-readable summary. |
| D5 | Perf attribution | boringssl-vs-rustls handshake delta accepted as negligible after pooling/resumption/X25519/bypass (user-confirmed). Zero-alloc drain operates at body-stream level under wreq; true socket-level drain only on the H3 path. Accepted. |

## 3. Architecture (single process)

```
                 ┌────────────────────────── 100ms tick ───────────────┐
                 │                                                     │
 Intents (intended_send_time)            TargetRate (watch)           Snapshot
 Scheduler ──bounded mpsc──> WorkerPool ──wreq/quinn──> Target        │
     ^                          │  │                                  │
     │            connections←──┘  └──record────► TelemetryEngine ◄────┘
     │        rate←─watch────── Controller(AIMD/Pulse/…) ◄─ snapshots ──┘
     │                                                          │ watch
     │                                              TUI task ◄──┤ WS broadcasts ◄── axum Web
```

- **Runtime**: one multi-threaded tokio runtime (`worker_threads = available cores`). Worker pool = `--concurrency` tasks (default ~ cores), each pulling `Intent`s from a bounded mpsc (capacity ≈ 4×workers, backpressure available to scheduler).
- **Scheduler** (`engine/scheduler.rs`): leaky-bucket pacing. Maintains `next_send` accumulator against a monotonic clock; reads target RPS from `watch` channel. Each intent carries `intended_send_time`. Options: uniform spacing (`--rate`, default) or Poisson jitter (`--poisson`). Scheduler is decoupled from execution → **coordinated omission eliminated**: latency is recorded `completion − intended_send_time` (worker/scheduler lag never hides tail samples); scheduler lag is tracked separately (`scheduler_lag` gauge).
- **Controller** (`controller/`): 100ms strategy tick fed by telemetry `Snapshot` (p50/p95/p99, error rates, `dLat/dt` over sliding window). Publishes new target rate to scheduler via `watch::Sender<u64>`. Strategies as state machine:
  - `Fixed { rate }` (open loop; default when `--rate` given)
  - `Knee` (AIMD): `rate += α` while `dLat/dt < δ && errRate == 0`; `rate *= β` otherwise; α/β/δ configurable, defaults documented. Pin-then-probe near the knee.
  - `Pulse` (square wave: duty cycle, period)
  - `Brownout` (sustained % of discovered peak / manual ceiling)
  - `Manual` (live override via TUI hotkeys / web / `watch`)
- **Mutation engine** (`controller/mutation.rs`): activates when 403-ratio exceeds threshold in window (or `--mitigate-always`); cycles mitigation headers (X-Forwarded-For, X-Real-IP, Client-IP, True-Client-IP…) and applies path normalizations (`/%2e/`, `//`, `;params`) per-request, deterministic-random.
- **Telemetry** (`telemetry/`): `histogram::AtomicHistogram` (lock-free) per latency class: total (CO-corrected), connect, TTFB, and per-run-global `AtomicU64` counters for status classes (1xx/2xx/3xx/4xx/5xx buckets by exact code up to 599), transport errors, bytes in/out. 100ms tick snapshots via `load()` into a `Snapshot` struct; `derivative.rs` computes `dLat/dt` over a sliding 5×100ms window of p99; `error_classifier.rs` maps errors to classes (connect/timeout/reset/proxy/tls).
- **Engines** (`engine/`): trait `Protocol { async fn execute(&mut self, Intent) -> Outcome }`.
  - `h1.rs` / `h2.rs`: wreq `Client` (one per worker/pool id) with `TlsSettings`: `danger_accept_invalid_certs(true)`, X25519-only curve preference (config flag `--x25519-only`, default on), `permute_extensions` for random-profile coherence, ALPN by version flag. Pool sizing via wreq/hyper defaults + `pool_idle_timeout` tuned for load (never expire during run).
  - `h3.rs`: `quinn::Endpoint` with custom `AsyncUdpSocket` impl (direct UDP or SOCKS5-UDP relay below), rustls client with `danger::ServerCertVerifier` bypass, X25519-only, ALPN `h3`. `h3` client driver per connection (0-RTT off; resumption default on).
  - `ws.rs`: wreq WebSocket upgrade. Modes: hold-n (target conn count), churn (open/close rate), tx rate, rx drain (fixed buffer, count bytes/frames, no parse unless `--ws-echo-verify`).
  - `drain.rs`: thread-local 8KB fixed buffer; `bytes_stream()` → read-loop that never allocates/converts; counts bytes.
  - `socks5.rs`: custom SOCKS5 client (auth method 0x02 user/pass, CONNECT, and **UDP ASSOCIATE 0x03** with relay discovery + 10-byte datagram header wrap/strip + TCP control-connection hold). Used by (a) wreq via `socks5://user:pass@host:port` proxy URL, (b) h3 via the custom `AsyncUdpSocket` wrap (not expressible in wreq).
  - `pool.rs` dispatches intents to the right engine per URL scheme/version flags; owns per-worker engine instances.
- **TLS** (`tls/`): `verifier.rs` = rustls danger verifier for the quinn path (always-accept, log-once); `fingerprints.rs` = wreq-util profile mapping + per-connection randomization + coherent UA/headers/ALPN injection.
- **URL templating** (`engine/urltemplate.rs`): `path?query=[a-z][1-9]` charclass expansion — parser handles literal text + `[a-z]`/`[1-9]` charclasses; samples fresh per request. Custom headers via repeatable `--header k: v`, body via `--body`/`--body-file`/`--body-stream` (later)+ content-type; methods GET/POST/PUT/…/custom.
- **UI** (`ui/`): thin pub-sub bus over the same 100ms `Snapshot` (`tokio::sync::watch` for state + `broadcast` for sparkline history ring + control messages channel). `tui.rs`: ratatui layout per spec mock (target/status/runtime header, throughput bars, p50/p90/p99 sparklines, telemetry matrix incl. `dLat/dt` verdict STABLE/DEGRADING, strategy pane, hotkeys). Hotkeys: `[K]` knee-hunt, `[B]` brownout, `[P]` pulse, `[E]` entropy toggle (payload entropy randomization flag), `[Q]` graceful drain, `[+/-]` manual rate, `[ ]` pause. `web.rs`: axum, `/` (embedded static HTML single page, `include_str!`), `/ws` pushing the same snapshot JSON at 100ms, accepting control messages (same set as hotkeys). No JS build tooling — one vendored file, no framework.
- **Report**: text table (runtime, RPS target vs actual, count, status distribution %, transport errors, CO-corrected latency p50/mean/p90/p95/p99, bytes/sec, connect stats) + `--json` equivalent. Written at graceful end or duration end.

## 4. Crate & toolchain choices

- Single binary crate `k2`, edition 2024, Rust via MacPorts toolchain.
- Core deps (pin exact in `Cargo.lock`): `tokio` (full), `wreq 6.0.0-rc` + `wreq-util` (emulation presets), `quinn`, `h3`, `h3-quinn`, `rustls`, `hyper` (via wreq; direct dep only for drain/socket helpers), `axum`, `tokio-tungstenite` (fallback if wreq WS needs bridging — prefer wreq WS), `ratatui`, `crossterm`, `clap` (derive), `serde`+`serde_json`, `histogram 1.2`, `rand`, `tracing`+`tracing-subscriber`, `libc`, `anyhow`/`thiserror`.
- Build prerequisites for BoringSSL: cmake, go, perl — **present on this machine (verified)**.
- Cargo features: `impersonate` (wreq) is core; `linux-sockets` cfg-gated feature for raw source binding. No `--no-default-features` story needed in v1.

## 5. Milestones (build order, each ends compiling + tested)

1. **M0 Scaffold** — Cargo.toml, module tree per spec §7, clap config surface, tracing setup, CI workflow (fmt, clippy -D warnings, test, release build), README skeleton with authorized-targets notice, `.gitignore`, first commit.
2. **M1 Telemetry core** — AtomicHistogram wrappers, counter sets, `Snapshot`, `dLat/dt` sliding window, status/error classifier. Unit tests.
3. **M2 Engine core (H1/H2 via wreq) + scheduler + headless engine** — intents, worker pool, fixed-rate + poisson scheduling, drain, CO-corrected recording, final text/JSON report, graceful shutdown (cancellation token, socket drain). Integration test against local axum harness (fixed rate adherence, counts, report shape). **← first end-to-end usable binary.**
4. **M3 Closed-loop control** — controller loop (100ms), Fixed/Knee-AIMD/Pulse/Brownout/Manual, mutation engine (403-triggered header/path cycling), live rate channel. Unit tests (AIMD math on synthetic snapshot sequences; derivative threshold; mutation grouping).
5. **M4 TLS identity layer** — fidelity randomization per connection, X25519-only setting, bypass verifier (both wreq TlsSettings and quinn rustls verifier), `--tls-verify` inverse, entropy payload toggle.
6. **M5 Proxies** — HTTP CONNECT + SOCKS5 (wreq proxy config) for TCP paths; custom SOCKS5 client with UDP ASSOCIATE + 10-byte header wrap/strip + control-conn hold; harness SOCKS5 stub server in tests exercising CONNECT + UDP relaying to a local UDP sink.
7. **M6 HTTP/3 engine** — quinn Endpoint (direct + via SOCKS5 UDP relay), h3 request cycle, bypass verifier, integration test against local quinn/h3 server.
8. **M7 WebSocket engine** — hold/churn/message-rate modes, rx drain, integration test with local WS echo server (hold N, churn to new N).
9. **M8 UI layer** — telemetry bus, ratatui TUI (all panes + hotkeys + graceful drain), axum web dashboard + WS control-message echo tests.
10. **M9 Linux socket opts + hardening** — cfg-gated `IP_BIND_ADDRESS_NO_PORT` (Linux opt 24) plumbing, source-IP/AnyIP bind surface on the H3 path + config (`--interface`, `--source-subnet`, requires CAP_NET_ADMIN, warn when missing), signal handling (SIGINT graceful), run bookkeeping (requests/duration/budget cutoffs), README/AGENTS.md finalization, release build.

## 6. Validation plan

- `cargo fmt --check && cargo clippy --all-targets -D warnings && cargo test` green at every milestone boundary.
- **CO-correctness test (flagship)**: harness server that stalls responses under load; assert recorded latencies are anchored to intended-dispatch time — the reported latency distribution must NOT dip artificially as the target slows.
- **Rate adherence**: fixed 500 RPS × 10 s against local server ⇒ actual within ±5%.
- **Closed-loop behavior**: harness that degrades after X requests ⇒ K2 must decrease rate (β step) within one tick and log `DEGRADING`; must recover when target speeds (rate increases).
- **Mutation trigger**: harness returning >threshold 403s ⇒ mitigation headers observed in accepted requests.
- **H3 + SOCKS5 UDP**: loopback quinn server reachable through the socks5-UDP relay stub ⇒ request success + byte accounting.
- **WS**: hold 1k/churn loop on local echo server stable for 5s, clean drain on `[Q]`.
- **Performance smoke (informational)**: 10k RPS, 10 s, loopback, plain HTTP ⇒ process CPU well under one core, RSS < ~64 MB, zero stalls in `dLat` reporting. Informational gate, not CI-blocking.
- **Manual TUI check**: attach interactive run and confirm sparklines/hotkeys render and exit cleanly (implementer runs once interactively).

## 7. Risks & mitigations

- **wreq 6.x is an rc** (rapid churn): pin exact rc version in `Cargo.lock`; API confined to `engine/` + `tls/` modules; fallback pin to plain `wreq 5.3` documented if a breaking change blocks.
- **BoringSSL build env**: cmake/go/perl verified present on this machine (macOS arm64); Windows support not provided in v1.
- **quinn/h3 rc API drift**: same mitigation as #2.
- **wreq lacks raw-TCP connector hooks** ⇒ `IP_BIND_ADDRESS_NO_PORT`/AnyIP source-binding not applicable to wreq TCP connects — documented limitation, plumbing exists for H3/quinn and future seams.
- **Session permission caveat (this environment)**: current session's permission rules deny `cargo *` and mutating `git` commands; the implementing session must be granted `cargo *` and `git add`/`git commit` (or the work cannot compile/run). Flagged to the user before implementation.
- **Dual-use tool**: README carries a hard authorized-targets-only notice + usage banner in `--help`.

## 8. Out of scope (explicit)

- Spec §9 distributed swarm: gRPC control plane, WireGuard tunnels, SSH/Docker/Podman/Nomad/K8s/Fly.io provisioning (seams only: `TelemetrySink`, `ControlPlane` traits).
- Advanced scraping tooling beyond the header/path mutation set named in spec §5.
- Recording/replay, HAR import, DNS-over-HTTPS, charts beyond spec panes, plugin system.
- Formal capacity-model fitting; knee-pinning stays empirical.

## 9. Open items for implementation (defaults chosen, changeable in review)

- Exact wreq rc pin + emergent `h3`/`quinn` versions at time of build (latest stable pairs).
- License: propose MIT (file placed in M0, easily changed).
- TUI default rate for Manual override step sizes (100 RPS default).
