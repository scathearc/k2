//! One-time e2b template provisioning: scaffolds the node image (k2 binary +
//! node-server start command) and shells out to the e2b CLI to build it.

use anyhow::anyhow;

/// Scaffold `./k2-swarm-provision/` and (when the e2b CLI is available) build
/// the template.
///
/// The e2b CLI command is `e2b template create <name>` (NOT `template build`
/// — that subcommand does not exist). The start command and ready probe are
/// passed as `--cmd` / `--ready-cmd` flags; the old `e2b.toml` SDK format is
/// not read by the CLI, so we no longer emit it.
pub async fn provision(template: &str) -> anyhow::Result<()> {
    let dir = std::path::Path::new("k2-swarm-provision");
    std::fs::create_dir_all(dir).map_err(|e| anyhow!("mkdir: {e}"))?;

    // The node binary must exist: prefer an explicit copy in the scaffold dir,
    // then a linux-musl release build.
    let bin = dir.join("k2");
    if !bin.exists() {
        let candidates = [
            std::path::PathBuf::from("target/x86_64-unknown-linux-musl/release/k2"),
            std::path::PathBuf::from("target/release/k2"),
        ];
        let found = candidates.iter().find(|c| c.exists());
        match found {
            Some(src) => {
                std::fs::copy(src, &bin).map_err(|e| anyhow!("copy k2 binary: {e}"))?;
                eprintln!("provision: copied {} → {}", src.display(), bin.display());
            }
            None => {
                return Err(anyhow!(
                    "no k2 binary found. Build a linux node binary first:\n  \
                     rustup target add x86_64-unknown-linux-musl\n  \
                     cargo build --release --target x86_64-unknown-linux-musl\n  \
                     then copy it to {}/k2 (or download a release binary)",
                    dir.display()
                ));
            }
        }
    }

    // Hardening script baked into the node image: runs at container start and
    // raises the FD / process / TCP / NIC ceilings so a swarm node can actually
    // sustain the concurrency the scheduler commands. Idempotent; failures on
    // a particular knob (no ethtool, no systemd) are non-fatal.
    let harden = r#"#!/usr/bin/env bash
set -euo pipefail

apt-get update -y && apt-get install -y ethtool irqbalance || true
systemctl enable --now irqbalance || true

cat <<'EOF' > /etc/security/limits.d/99-nofile.conf
*       soft    nofile    1048576
*       hard    nofile    1048576
*       soft    nproc     1048576
*       hard    nproc     1048576
root    soft    nofile    1048576
root    hard    nofile    1048576
EOF

mkdir -p /etc/systemd/system.conf.d/
cat <<'EOF' > /etc/systemd/system.conf.d/99-limits.conf
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=1048576
DefaultTasksMax=infinity
EOF
systemctl daemon-reexec || true

modprobe tcp_bbr 2>/dev/null || true
cat <<'EOF' > /etc/sysctl.d/99-high-concurrency.conf
fs.file-max = 2097152
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_tw_buckets = 1440000
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
vm.swappiness = 10
vm.max_map_count = 262144
EOF
sysctl --system || true

ulimit -n 1048576 || true

PRIMARY_IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -n1 || true)
if [[ -n "${PRIMARY_IFACE:-}" ]] && command -v ethtool &>/dev/null; then
    MAX_RX=$(ethtool -g "$PRIMARY_IFACE" 2>/dev/null | awk '/Pre-set maximums:/,/Current hardware settings:/' | awk '/RX:/ {print $2}' | head -n1 || true)
    MAX_TX=$(ethtool -g "$PRIMARY_IFACE" 2>/dev/null | awk '/Pre-set maximums:/,/Current hardware settings:/' | awk '/TX:/ {print $2}' | head -n1 || true)
    if [[ "${MAX_RX:-0}" =~ ^[0-9]+$ ]] && [[ "${MAX_TX:-0}" =~ ^[0-9]+$ ]] && [[ "$MAX_RX" -gt 0 ]] && [[ "$MAX_TX" -gt 0 ]]; then
        ethtool -G "$PRIMARY_IFACE" rx "$MAX_RX" tx "$MAX_TX" || true
    fi
fi
"#;

    let dockerfile = r#"FROM ubuntu:24.04
RUN apt-get update && apt-get install -y ca-certificates curl iproute2 && rm -rf /var/lib/apt/lists/*
COPY k2 /usr/local/bin/k2
RUN chmod +x /usr/local/bin/k2
COPY harden.sh /usr/local/bin/k2-harden.sh
RUN chmod +x /usr/local/bin/k2-harden.sh && /usr/local/bin/k2-harden.sh
"#;
    std::fs::write(dir.join("Dockerfile"), dockerfile)
        .map_err(|e| anyhow!("write Dockerfile: {e}"))?;
    std::fs::write(dir.join("harden.sh"), harden).map_err(|e| anyhow!("write harden.sh: {e}"))?;

    eprintln!("provision: scaffold written to {}", dir.display());
    eprintln!(
        "provision: invoking `e2b template create {template}` (needs the e2b CLI + E2B_API_KEY)…"
    );

    let out = tokio::process::Command::new("e2b")
        .args([
            "template",
            "create",
            template,
            "--cmd",
            "k2 --node-server 9601",
            "--ready-cmd",
            "curl -fsS http://localhost:9601/health",
        ])
        .current_dir(dir)
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            eprintln!("provision: template '{template}' built successfully");
            if !stdout.trim().is_empty() {
                eprintln!("provision: {stdout}");
            }
            eprintln!("provision: you can now run: k2 <target> --swarm <N> --provider e2b");
            Ok(())
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            let stdout = String::from_utf8_lossy(&o.stdout);
            Err(anyhow!(
                "e2b template create failed (exit {}):\n{stderr}{stdout}\n\
                 (re-run manually: cd {} && e2b template create {template} \
                  --cmd \"k2 --node-server 9601\" \
                  --ready-cmd \"curl -fsS http://localhost:9601/health\")",
                o.status.code().unwrap_or(-1),
                dir.display()
            ))
        }
        Err(e) => Err(anyhow!(
            "e2b CLI not found ({e}). Install it (npm i -g e2b@latest) and authenticate with E2B_API_KEY, then:\n  cd {} && e2b template create {template} --cmd \"k2 --node-server 9601\" --ready-cmd \"curl -fsS http://localhost:9601/health\"",
            dir.display()
        )),
    }
}
