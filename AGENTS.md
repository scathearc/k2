# K2 — Agent Workspace Notes

Single-binary Rust load-testing engine. Spec: `SPEC.md`. Resolved design
forks: `.kilo/plans/1792053875970-k2-implementation-plan.md` (authoritative
for architecture decisions — read before changing engines/TLS/scheduler).

## Commands

- Build: `cargo build --release` (BoringSSL needs cmake/go/perl — present on
  this machine; first build compiles boring via wreq).
- Verify: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
- Smoke: `./target/release/k2 http://127.0.0.1:PORT/ --rate 200 -d 3 --no-tui`
- TUI smoke through a pty: `script -q /dev/null ./target/release/k2 <url> --tui -d 2`

## Load-bearing implementation facts (do not regress)

- **Coordinated omission**: latency = `completed − intended_send`
  (`telemetry::Outcome::latency_ns`). Scheduler leaks a bucket anchored to
  wall-clock absolute time; never re-anchor backwards. Dispatch lag is a
  separate histogram (`lag`).
- **Histograms are hand-rolled** (`telemetry/histogram.rs`): logarithmic
  bucketing, SUB_BITS=7, lock-free `AtomicU64` counts, `drain()` per 100ms
  tick merged into a cumulative `Agg`. `index_for(0)` must never run (guard
  `v.max(1)`).
- **TLS**: wreq 6.0.0-rc.x + wreq-util. Emulation presets are picked
  PER REQUEST (`fingerprints::pick`) — that is the identity engine. Cert
  bypass default-on via `tls_cert_verification(false)`; `--tls-verify`
  restores roots (webpki-roots).
- **HTTP/3**: quinn 0.11 + h3 0.0.8 + h3-quinn. The h3 `Connection` must be
  continuously driven (`poll_close`) — one spawned driver task per connection.
  rustls provider is X25519-only + TLS13_AES_128_GCM only.
- **SOCKS5 UDP ASSOCIATE** (`engine/socks5.rs`): custom `quinn::AsyncUdpSocket`
  wraps TX in the 10-byte header (RSV/FRAG/ATYP/DST) and peels RX; TCP control
  conn is held in `Socks5UdpSocket._control` — dropping it kills the relay.
  quinn `UdpPoller` implemented via tokio `poll_send_ready`.
- **axum 0.8** route captures use `{param}` NOT `:param`.
- **Body templating**: `--body`/`--body-file` share the URL charclass grammar
  via `UrlTemplate::parse_body` (JSON-safe: a `[...]` group is a class only if
  its atoms are pure class chars — `[1,2,3]`/`[]` stay literal; probe-scan on
  a cloned iterator, commit on success). Expansion lives in
  `Materializer::materialize` and WINS over `--entropy` (byte-randomizing
  would destroy JSON). Non-UTF-8 bodies stay verbatim.
- **wreq ws module path**: `wreq::ws::message::Message` (not `wreq::ws::Message`).
- **Mutation engine stickiness** (`controller/mutation.rs`): 3-level ladder
  (L1 IP headers → L2 path mutation → L3 method-overrides capped by
  `MitigateCfg.method_override`). `tick_mitigation()` implements the
  hysteresis: 403-ratio spike → escalate + reset clean streak; proven levels
  HOLD (demotion only after `DEMOTE_AFTER_TICKS`=30 clean ticks). Tool
  ranking = per-variant 403-rate EMA (`ALPHA`=0.3) fed by
  `report_result(tags, is_403)` from `engine/pool.rs` (tags ride on
  `RequestSpec.mitigation_used`); 1-in-10 deterministic exploration keeps
  discovery alive. Do NOT make demotion instant — that re-bills a 403 per
  request on under-attack targets (user decision).
- **Engine consolidation (user decision)**: ONE stack — wreq/BoringSSL for
  H1/H2/WS; quinn for H3. There is no separate "fast path" rustls engine.

- **Blocked family**: 403 and 405 are THE SAME signal (user decree); mutation
  trigger + tool EMA use `is_blocked()` / `BLOCKED_STATUSES`. Tool families:
  IP headers (8), **IP_DUP** (`X-Forwarded-For` twice per request — raw-dupe),
  method overrides (9 combos). `MitTag{dup}` rides on
  `RequestSpec.mitigation_used`.
- **Status-first control (user decree)**: latency is a QUEUE signal, not a
  health signal (5x latency w/ 200s = fine). Default `--degrade-signal status`
  (non-2xx+error ratio ≥ `--degrade-status-threshold` 0.02 → degrading);
  latency derivative only via `latency`/`both`. Never re-add latency as the
  default primary signal.
- **Scheduler grid invalidation**: rate updates mark `grid_dirty` →
  `next_arrival = now`. A parked scheduler (rate-0 → dt=100s) with stale
  future slots otherwise sleeps through its rate commands (found via swarm).
  Any scheduler change must keep this.
- **Swarm** (`src/swarm/`): coordinator pulls snapshots + pushes rate over
  node public URLs (`https://9601-{sandboxId}.e2b.app`); nodes are
  `k2 --node-server 9601` inside an e2b template (one-time
  `k2 --swarm-provision k2-node` with a linux-musl binary in
  ./k2-swarm-provision/). FakeProvider = in-process node servers (NEVER spawn
  child processes in tests — current_exe is the test runner). Merge =
  per-node cumulative-bucket slot + delta windows. Node campaign =
  scheduler+engine only (NO controller — coordinator owns the loop).
- **Swarm UI**: coordinator feeds merged fleet data into a display-bus
  `Telemetry` via `swarm_tick` each 100ms; the stock TUI/web attach to it
  unchanged (`--tui`/`--web` on the coordinator). `drain_window` returns
  AND RESETS counters (it returns lat buckets too; p99 derives from the
  drained buckets, not post-drain reads). Window rps math uses the true
  `window_ms` — poll deltas arrive in ~500ms chunks and assuming TICK_MS
  inflates rps ~5×. Do not re-add post-drain `window_p99_ns` reads.

## Testing

`tests/common/mod.rs` spins a local axum harness (latency injection, 403
storm, WS echo, fallback for mutated paths). Flagship test:
`coordinated_omission_anchoring` — injects 350ms latency mid-run and asserts
the p99 carries it. Keep `-c` (workers) ≥ concurrent-in-flight expectation in
tests with slow endpoints.

## Session permissions history

2026-10-15: `cargo` runs allowed in code sessions (plan sessions had `cargo`
denied). Mutating `git` (add/commit) was denied in the plan session; verify
before committing in a fresh session.
