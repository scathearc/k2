K2: High-performance load testing tool

Technical Specification & Architecture Notes
1. Executive Summary & Design Philosophy
2. 
K2 is a load generation testing framework and tool, aiming to bridge the gap between theoretical hardening and true hardening of infrastructure for deployment. It enables preparation and validation of production systems to be resilient to real-world situations and should only ever be used on authorized targets.

Traditional load testing frameworks operate on a open-loop, brute-force model. They focus on volumetric payload delivery that often triggers simplistic rate limiters or introduces severe Coordinated Omission metrics skew.

This engine implements an interactive, closed-loop cybernetic system designed to maximize computational and economic efficiency. The core objective is to minimize client-side resource utilization (CPU cycles, memory allocations, and network socket footprint).

+-----------------------------------------------------------------------+
|                       CLOSED-LOOP CONTROL PLANE                       |
|  +-------------------+    Telemetry Ticks    +---------------------+  |
|  |  Telemetry Engine | --------------------> |  Policy Controller  |  |
|  | (HDR Histograms)  |                       |  (AIMD / PID Loops) |  |
|  +-------------------+                       +---------------------+  |
|            ^                                            |             |
|            | Metrics                                    | Target Rate |
|            |                                            v             |
|  +-----------------------------------------------------------------+  |
|  |                     Worker Pool (Tokio/Hyper)                    |  |
|  +-----------------------------------------------------------------+  |
+-----------------------------------||----------------------------------+
                                    || Egress / Ingress
                                    v
+-----------------------------------------------------------------------+
|                             TARGET SYSTEM                             |
|       (Maximizing Server-Side Parsing & Cryptographic Overhead)       |
+-----------------------------------------------------------------------+
Guiding Principles
Resource Efficiency: Absolute minimal resource consumption on the host/worker machines. 
Closed-Loop Feedback: Continuous telemetry analysis dynamically modulates traffic dynamics in real-time, eliminating the need for fixed pre-baked scripts.
Coordinated Omission Elimination: Decouple packet generation timing from target response latency to capture genuine latency distribution profiles during target degradation.


2. High-Level Architecture
The system is decoupled into four core runtime modules:+-----------------------------------------------------------------------+
|                            USER INTERFACE                             |
|      Interactive TUI (Ratatui)   |   Embedded Web UI (Axum)           |
+----------------------------------+------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                           POLICY CONTROLLER                           |
|       AIMD Rate Control   |   PID Loops   |   Strategy State Machine   |
+----------------------------------+------------------------------------+
                                   |
                                   v
+----------------------------------+------------------------------------+
|                          TELEMETRY ENGINE                             |
|       HDR Lock-Free Histograms   |   Latency Derivatives (dLat/dt)    |
+----------------------------------+------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                       HIGH-PERFORMANCE WORKERS                        |
|        Rust Core   |   Tokio Async   |   Hyper / Quinn Protocol Stack |
+-----------------------------------------------------------------------+

Control Surface: Features an interactive Terminal UI built with ratatui and crossterm, supplemented by an optional local embedded web dashboard serving WebSocket telemetry via axum. Telemetry updates strictly on a 100ms cycle.
Policy Controller: Encapsulates the closed-loop control system. Hosts Additive Increase / Multiplicative Decrease (AIMD) controllers, PID loops, dynamic dynamic strategy state machines, and scheduling offset correctors.
Telemetry Engine: High-Dynamic-Range (HDR) lock-free atomic histograms recording sub-microsecond timing precision, alongside real-time latency derivative detectors ($\frac{d\text{Lat}}{dt}$), HTTP status classifiers, and system error rate counters.
High-Performance Worker Pool: Fully asynchronous engine written in Rust over the tokio runtime, leveraging hyper (HTTP/1.1 & HTTP/2), quinn (HTTP/3 / QUIC), and wreq(boringssl) for efficient network execution that has high fidelity in the network stack to browsers


3. Layer-7 Optimizations & Client Efficiency
To achieve maximum efficiency on client hardware, low-level optimizations bypass standard OS and protocol overheads.

Optimization Subsystem
Mechanics
Technical Impact
TLS Verification Bypass
Implements rustls::client::danger::ServerCertVerifier
Eliminates cert validation, RSA/ECDSA signature verification, and OCSP lookups. Saves ~70% client TLS handshake CPU time.
Cipher & Curve Pinning
Restricts ECDH to Curve25519 (X25519)
Avoids expensive NIST curves (e.g., P-384) and legacy RSA key exchanges on client runtime.
Session Resumption
PSK session resumption and thread-local ephemeral key reuse
Bypasses repeat asymmetric curve processing on client across outbound socket pools.
Zero-Allocation Stream Draining
Fixed thread-local 8KB scratch buffer read loop
Discards incoming response frames directly at the socket level without heap allocation or string conversion.
Socket Binding Scaling
Sets libc::IP_BIND_ADDRESS_NO_PORT (Linux Option 24)
Delays ephemeral source port allocation to handshake execution, bypassing the 65,535 local port limit.
AnyIP Subnet Distribution
Binds raw sockets across local AnyIP route definitions
Assigns full /24 (IPv4) or /64 (IPv6) blocks to loopback, rotating client IP footprints without physical adapters.
Identity Engine
Coherent User-Agent, ALPN, and extension ordering matching
Present browser signatures (e.g., Chrome 151+) while preserving client-side low-overhead TLS execution. Defaults to randomized TLS fingerprint per request.

Zero-Allocation Stream Draining Pattern
Instead of deserializing payloads, client streams drain raw socket bytes directly into thread-local static memory blocks:           
           +-------------------------------------------------+
           |             Inbound Network Socket              |
           +-------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|              Thread-Local Scratch Buffer (Fixed 8KB Block)            |
|       - Single allocated buffer reused across all stream loops        |
|       - Read bytes directly off socket wire                           |
|       - Instant pointer reset (No heap reallocations)                 |
+-----------------------------------------------------------------------+
                                    |
                                    v
           +-------------------------------------------------+
           |        Payload Discard / Drop Instantly         |
           +-------------------------------------------------+


4. Residential Proxy & Protocol Support
The engine supports transparent network traversal, including complex UDP proxying for modern HTTP/3 connections
.+---------------+        TCP Control Stream (Method 0x02)         +-----------------+
|               | ----------------------------------------------> |                 |
|               | <---------------------------------------------- |                 |
|               |             UDP ASSOCIATE (Cmd 0x03)            |                 |
|               | ----------------------------------------------> |                 |
| Engine Worker | <---------------------------------------------- | SOCKS5 Proxy    |
|               |             Relay IP + UDP Port                 |                 |
|               |                                                 |                 |
|               |  Encapsulated Datagrams (10-byte SOCKS5 Header) |                 |
|               | ==============================================> |                 |
+---------------+                                                 +-----------------+
                                                                           ||
                                                                           || Native QUIC
                                                                           v
                                                                  +-----------------+
                                                                  | Target Host H3  |
                                                                  +-----------------+
Protocols Supported
HTTP Tunneling: HTTP CONNECT tunneling via residential proxy nodes.
SOCKS5 Proxying: Fully compliant TCP proxying with support for optional username/password authentication.
SOCKS5 UDP ASSOCIATE for HTTP/3 (QUIC):
Establishes a TCP control connection to the proxy server with authentication (Method 0x02).
Issues a UDP ASSOCIATE command (Command 0x03) to discover the assigned proxy UDP relay address and port.
Maintains the TCP control connection open to preserve the active relay session.
Wraps a custom quinn::AsyncUdpSocket driver around outbound packets, prepending a 10-byte SOCKS5 UDP encapsulation header on egress and stripping it on ingress:

$$\text{Header Format: } \underbrace{\text{RSV}}{2\text{ bytes}} \parallel \underbrace{\text{FRAG}}{1\text{ byte}} \parallel \underbrace{\text{ATYP}}{1\text{ byte}} \parallel \underbrace{\text{DST.ADDR}}{4\text{ or } 16\text{ bytes}} \parallel \underbrace{\text{DST.PORT}}_{2\text{ bytes}}$$


5. Closed-Loop Adaptive Strategies & Dynamics
                                 +-----------------------+
                                 |  Continuous Execution |
                                 +-----------------------+
                                             |
                                             v
                                 +-----------------------+
                                 | Telemetry Read: p99,  |
                                 | error rates, dLat/dt  |
                                 +-----------------------+
                                             |
                   +-------------------------+-------------------------+
                   |                                                   |
                   v                                                   v

     [ Latency Derivative Low ]                        [ Latency Derivative High ]

    (dLat/dt < Threshold & Err = 0)                   (dLat/dt > Threshold OR Err > 0)
                   |                                                   |
                   v                                                   v
     +---------------------------+                       +---------------------------+
     |  Additive Increase (AIMD) |                       | Multiplicative Decrease   |
     |   Increase Rate (+ΔRPS)   |                       |    Step Down Rate (-β%)   |
     +---------------------------+                       +---------------------------+
                   |                                                   |
                   +-------------------------+-------------------------+
                                             |
                                             v
                                 +-----------------------+
                                 |Pin Constant Near Curve|
                                 |     Knee Threshold    |
                                 +-----------------------+
Automated Saturation Hunting (Knee-of-Curve / AIMD)
Monitors $p50$, $p95$, and $p99$ tail latency trends at 100ms intervals.
Evaluates the rate of change in latency over time:

$$\frac{d\text{Lat}}{dt} = \frac{\text{Lat}{t} - \text{Lat}{t-\Delta t}}{\Delta t}$$

A rapid rise in $\frac{d\text{Lat}}{dt}$ signals that target request queues are filling up and performance is degrading.
An Additive Increase / Multiplicative Decrease (AIMD) algorithm dynamically adjusts throughput, keeping target performance right at its maximum capacity line:

$$\text{Rate}_{t+1} = \begin{cases} \text{Rate}_t + \alpha & \text{if } \frac{d\text{Lat}}{dt} < \delta \text{ and } \text{Errors} = 0 \ \text{Rate}_t \times \beta & \text{if } \frac{d\text{Lat}}{dt} \ge \delta \text{ or } \text{Errors} > 0 \end{cases} \quad (\alpha > 0, 0 < \beta < 1)$$
Anti-Warmup & Resonance Modulation
Identifies target server optimizations like JIT compilation, connection pool expansion, and cache warming.
Applies dynamic traffic patterns—such as square-wave pulsing, variable payload entropy, and endpoint cycling—to prevent the target from stabilizing its caches.
Coordinated Omission Elimination
Decouples request scheduling timers (using Poisson / Leaky Bucket generators) from worker execution threads.
If a target system slows down and delays worker threads, the scheduler explicitly logs the intended execution time vs. actual completion time. This prevents artificial drops in reported latency metrics during high target load.
Adaptive L7 Response Handling
Automatically adapts when high rates of 403 status codes are detected.
Cycles through mitigation headers dynamically (e.g., X-Forwarded-For, X-Real-IP, Client-IP, True-Client-IP). (See reference "nomore403")
Modifies request path structures using path normalization strategies (/%2e/, //, ; path truncation).


6. Interactive Flight Deck (TUI / Web Control)
+-----------------------------------------------------------------------------------+
| TARGET: https://api.target.internal   | STATUS: RUNNING   | RUNTIME: 00:04:22     |
+-----------------------------------------------------------------------------------+
| THROUGHPUT (RPS)                                                                  |
| Target: 15,000 [██████████████████████████████████████████] Actual: 14,982        |
|                                                                                   |
| LATENCY SPARKLINE (p99)                                                           |
| 120ms |       _/\_                                                                |
|  45ms |   _/\_/    \__/\_                                                         |
|  12ms |__/               \_______________________________________________________ |
+-----------------------------------------------------------------------------------+
| TELEMETRY MATRIX                                                                  |
|   p50: 1.2ms  |  p90: 4.8ms  |  p99: 42.1ms  |  dLat/dt: +0.04 (STABLE)           |
|   HTTP 200: 98.4% | HTTP 403: 0.0% | HTTP 503: 1.6% | Transport Errors: 0          |
+-----------------------------------------------------------------------------------+
| ACTIVE STRATEGY: [ Knee-of-Curve AIMD ]                                           |
| HOTKEYS: [K] Knee Hunt  [B] Brownout  [P] Pulse  [E] Entropy  [Q] Graceful Drain  |
+-----------------------------------------------------------------------------------+
TUI Capabilities (ratatui)
Real-time Sparklines: Displays live ASCII charts for $p50$, $p90$, $p99$ tail latencies, error distributions, and target vs. actual requests per second (RPS).
Strategy Hotkeys: Allows real-time switching between operating modes (Knee-of-Curve, Brownout, Square-Wave Pulse, and Custom), manual rate adjustments, and payload entropy toggles.
Graceful Termination: Uses async cancellation tokens to cleanly shut down worker loops, ensuring sockets drain fully and statistical reports wrap up without hanging processes.
Local Web Interface (axum)
Serves a local web dashboard via WebSockets.
Exposes the same real-time control metrics and telemetry data for browser-based operations.


7. Module & Directory Structure
src/

├── main.rs                 # CLI entry point, flag parsing, and execution dispatch
├── controller/             # Policy and Strategy Control
│   ├── mod.rs              # Controller interface module
│   ├── aimd.rs             # AIMD saturation tracking algorithm
│   ├── pid.rs              # PID feedback loops for smooth rate adjustments
│   └── mutation.rs         # Dynamic HTTP header and path mutation engine
├── engine/                 # Core Execution Engine & Workers
│   ├── mod.rs              # Engine interface module
│   ├── pool.rs             # Tokio worker pool dispatcher
│   ├── h1.rs               # Hyper HTTP/1.1 protocol client
│   ├── h2.rs               # Hyper HTTP/2 multiplexed engine
│   ├── h3.rs               # Quinn HTTP/3 QUIC connection manager
│   ├── socks5.rs           # SOCKS5 UDP ASSOCIATE relay layer
│   └── drain.rs            # Zero-allocation response stream reader
├── telemetry/              # Telemetry & Metrics Collection
│   ├── mod.rs              # Telemetry interface module
│   ├── histogram.rs        # Atomic HDR histogram aggregators
│   ├── derivative.rs       # Latency derivative (dLat/dt) calculations
│   └── error_classifier.rs # HTTP status code and network error classifier
├── tls/                    # TLS Management
│   ├── mod.rs              # TLS interface module
│   ├── verifier.rs         # Custom certificate verification bypass
│   └── fingerprints.rs     # User-Agent and TLS fingerprint matching profiles
└── ui/                     # User Interfaces
    ├── mod.rs              # UI coordination layer
    ├── tui.rs              # Terminal Dashboard (Ratatui / Crossterm)
    └── web.rs              # Embedded Web UI Server (Axum / WebSockets)




8. Supported Modes & Functionality
K2 will support full-featured HTTP requests such as GET, POST, etc. on HTTP 1.1, HTTP2 and HTTP3/QUIC.

It will also support WebSockets, with the ability to initiate and hold large number of persistent websocket connections, churn through them, and communicate within the stream, while also being able to drain request bodies within the stream.

While it will support manual configuration flags similar to tools like (https://github.com/hatoo/oha) and many other prominent competitors, it will default to it's dynamically adjusted configuration being a core feature in order to maxmize the effectiveness of assisting operators in determining their infrastructure's true capacity.

Core requirements would be things like supporting randomized regex for target URL's e.g. mytarget.localhost/api/v1/someEndpoint?query=[a-z][1-9], adding custom headers, etc.

9. Universal Distributed Ephemeral Worker Architecture (Cloud-Agnostic Swarm) (Single-node capability first, adaptability ready for community-developed adapters)
K2 scales seamlessly across heterogeneous compute environments without relying on proprietary cloud Orchestrators or vendor-specific load generators. A single, statically linked Rust binary functions as both the master controller and the ephemeral worker node.
Worker Orchestration & Provisioning
SSH & Bare-Metal Nodes: Directly provisions raw nodes over SSH, deploying the standalone binary and initiating background worker processes with zero runtime dependencies.
Containerized Execution: Spawns short-lived container instances using Docker or Podman, dynamically injecting runtime configuration and target profiles via environment parameters.
Cluster Jobs: Dispatches ephemeral batch workloads across Nomad or Kubernetes clusters, executing scheduled stress campaigns on demand.
Micro-VM Edge Fleet: Deploys lightweight micro-virtual machines (e.g., Fly.io or Hetzner Cloud) near target regions to simulate geographically distributed traffic spikes.
Embedded Tunneling & Closed-Loop Control
WireGuard Tunnels: Workers establish encrypted overlay networks using embedded WireGuard tunnels, bypassing complex firewalls and NAT setups.
gRPC Control Channels: Bi-directional gRPC streaming handles real-time instruction pacing, telemetry ingestion, and closed-loop feedback adjustments acr


References: 
https://github.com/hatoo/oha
https://github.com/devploit/nomore403
https://github.com/0x676e67/wreq
https://github.com/artilleryio/artillery
