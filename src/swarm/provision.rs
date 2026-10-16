//! One-time e2b template provisioning: scaffolds the node image (k2 binary +
//! node-server start command) and shells out to the e2b CLI to build it.

use anyhow::anyhow;

/// Scaffold `./k2-swarm-provision/` and (when the e2b CLI is available) build
/// the template.
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

    let dockerfile = r#"FROM ubuntu:24.04
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY k2 /usr/local/bin/k2
RUN chmod +x /usr/local/bin/k2
"#;
    std::fs::write(dir.join("Dockerfile"), dockerfile)
        .map_err(|e| anyhow!("write Dockerfile: {e}"))?;

    let e2b_toml = format!(
        r#"template_id = "{template}"

[build]
dockerfile = "Dockerfile"

[start_command]
cmd = "k2 --node-server 9601"
ready_command = "curl -fsS http://localhost:9601/health"
"#
    );
    std::fs::write(dir.join("e2b.toml"), e2b_toml).map_err(|e| anyhow!("write e2b.toml: {e}"))?;

    eprintln!("provision: scaffold written to {}", dir.display());
    eprintln!(
        "provision: invoking `e2b template build --name {template}` (needs the e2b CLI + E2B_API_KEY)…"
    );

    let out = tokio::process::Command::new("e2b")
        .args(["template", "build", "--name", template])
        .current_dir(dir)
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => {
            eprintln!("provision: template '{template}' built successfully");
            eprintln!("provision: you can now run: k2 <target> --swarm <N> --provider e2b");
            Ok(())
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            Err(anyhow!(
                "e2b template build failed:\n{stderr}\n(re-run manually: cd {} && e2b template build --name {template})",
                dir.display()
            ))
        }
        Err(e) => Err(anyhow!(
            "e2b CLI not found ({e}). Install it (npm i -g e2b@latest) and authenticate with E2B_API_KEY, then:\n  cd {} && e2b template build --name {template}",
            dir.display()
        )),
    }
}
