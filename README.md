# K2

**Closed-loop, browser-fidelity load testing engine.** Single static Rust binary.

> ⚠️ K2 is a load testing tool. **Use only on targets you are authorized to test.**

```
k2 https://target.local/api/[a-z][1-9] -d 30
```

## Why K2

Traditional load generators (wrk, oha, ab) differ from real browser traffic in
two fatal ways, so their measurements lie on bot-managed targets:

1. **Fingerprint mismatch** — a Rust TLS ClientHello gets throttled or
   challenge-served, and you measure the WAF, not the service.
2. **Coordinated omission** — when the server slows down, the generator sends
   *less*, so the tail of the latency distribution is never observed.

K2 fixes both structurally:

- **Browser-grade TLS by default** — BoringSSL (via `wreq`) emits a
  market-share-weighted random browser profile *per request* (JA3/JA4 parity,
  coherent ALPN, header order, HTTP/2 settings). Cert verification is bypassed
  by default for CPU efficiency (`--tls-verify` restores it).
- **Coordinated-omission-corrected accounting** — the scheduler leaks a bucket
  at the commanded rate and every intent carries its `intended_send` instant;
  latency is recorded as `completion − intended_send`, so a stalled target
  *lengthens* reported latency instead of hiding it. Worker dispatch lag is
  tracked separately.
- **Closed-loop knee hunting** — an AIMD controller probes upward while
  `dLat/dt` stays flat and error rates are zero, and multiplies down (β)
  the moment the target saturates. The knee is found, not assumed.
- **Anti-warmup modulation** — square-wave pulse campaigns, brownout pinning
  at a fraction of the discovered knee, deterministic-random payload entropy,
  and a nomore403-informed header/path mutation engine that escalates when 403
  ratios spike.

## Feature map

| Area | What ships |
|---|---|
| Protocols | HTTP/1.1 + HTTP/2 via wreq/BoringSSL; HTTP/3 via quinn+h3 (X25519-only, TLS13, cert-bypass verifier); WebSocket hold/churn/send engine |
| Scheduling | Leaky-bucket absolute-time pacing, uniform or `--poisson` arrivals, micro-batching above ~5k RPS |
| Control | `Fixed`, `Knee` (AIMD α/β/δ), `Pulse` (square wave), `Brownout` (% of knee peak), `Manual` (live rate) with PID saturation guard and rate-limited transitions |
| Telemetry | Lock-free HDR histograms (logarithmic bucketing, ~0.4% top-end resolution), exact status counters, transport-error taxonomy, `dLat/dt` sliding-window verdict |
| Proxies | `http://`/`socks5://` CONNECT for TCP paths; custom SOCKS5 **UDP ASSOCIATE** driver so HTTP/3 rides residential relays (10-byte header wrap/peel on a custom `quinn::AsyncUdpSocket`) |
| Mutation | 403-ratio-triggered header rotation (X-Forwarded-For et al. with CGNAT-source randomization) + path normalizations (`/%2e/`, `//`, `;` truncation) |
| UI | ratatui TUI (sparklines, gauges, matrix, hotkeys) + axum web dashboard (WebSocket telemetry @100ms, REST control) — same bus |
| Output | Text report + `--json` / `--json-file` machine-readable summary |

## Install / build

```sh
cargo build --release        # boringssl needs cmake, go, perl
./target/release/k2 --help
```

## Usage

```sh
# Fixed rate, JSON summary
k2 https://t.local/api --rate 500 -d 30 --json

# Closed-loop knee hunt (default when --rate is omitted)
k2 https://t.local/api -d 60

# Pulse campaign through a residential SOCKS5 relay, H3
k2 https://t.local/api --strategy pulse --proxy socks5://u:p@res.example:1080 --http-version h3

# WebSocket churn: hold 1k conns, churn 50/s, 200 msg/s of 64B
k2 wss://t.local/ws --ws "1000:50:200:64" -d 120

# Randomized path templating (fresh value per request)
k2 "https://t.local/api/[a-z][1-9]?q=[a-f0-9]" --rate 300 -d 20

# Strategy hotkeys in the TUI: K knee · B brownout · P pulse · E entropy · +/- rate · Q drain
```

Exit codes: `0` healthy run · `2` config error · `3` every request failed.

## Architecture

```
Intents (intended_send_time)             TargetRate (watch)
Scheduler ──bounded mpsc──► Workers ──wreq/quinn──► Target
    ▲                          │                        │
    │        conn pools ◄──────┘                        │
    │  rate ◄──watch── Controller(AIMD/Pulse/…) ◄─ 100ms Telemetry snapshots
                                              │ watch
                                   TUI ◄──────┴──► Web(WS @100ms)
```

- `engine/scheduler.rs` — leaky-bucket arrival grid anchored to wall clock;
  rate changes re-space the grid forward, never backward.
- `telemetry/` — `AtomicHdr` lock-free HDR histogram (hand-rolled: O(1)
  recording, drain-per-tick), status/error classifier, `dLat/dt` detector.
- `controller/` — strategy state machine + AIMD + PID + mutation escalation.
- `engine/{client,h1,h2}.rs` — wreq/BoringSSL H1+H2 (per-request emulation).
- `engine/h3.rs` — quinn+h3, X25519-only ring provider, bypass verifier.
- `engine/socks5.rs` — SOCKS5 TCP CONNECT + UDP ASSOCIATE + quinn socket shim.
- `engine/ws.rs` — WS population manager (open/churn/send, drain inbound).
- `ui/{tui,web}.rs` — dashboards over one 100ms snapshot bus.

Design decisions and the resolved spec forks live in
`.kilo/plans/1792053875970-k2-implementation-plan.md`.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets   # zero warnings enforced
cargo test                   # unit + integration (local harness server)
```

The integration suite (`tests/`) spins a local axum harness with latency
injection, 403 storms, and a WebSocket echo to exercise the real engine:
rate adherence ±15%, CO anchoring under injected latency, mutation
escalation, graceful drain, WS churn, JSON report shape.

## Known limitations

- `IP_BIND_ADDRESS_NO_PORT`/AnyIP raw source binding is plumbed for the H3
  path only (wreq does not expose raw TCP connector hooks); Linux-only, needs
  CAP_NET_ADMIN.
- True socket-level zero-alloc drain applies to the H3 path; wreq paths drain
  at the body-stream level (equivalent CPU profile post-decryption).
- Cert verification bypass is the default (spec: client CPU efficiency) — run
  `--tls-verify` against anything you don't fully control.
