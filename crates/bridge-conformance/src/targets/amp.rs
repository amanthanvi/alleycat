//! Amp target — spawn `remora-amp-bridge` in stdio mode with
//! `AMP_BRIDGE_AMP_BIN` pointed at a real Amp CLI.

use std::process::Stdio;

use anyhow::{Context, Result, anyhow};
use tempfile::TempDir;
use tokio::process::Command;

use super::{TargetHandle, TargetSpawn, tee_stream};
use crate::transport::{JsonRpcClient, boxed_reader, boxed_writer};

pub async fn spawn(opts: TargetSpawn) -> Result<TargetHandle> {
    let bridge_bin = opts
        .bridge_bin
        .ok_or_else(|| anyhow!("amp target requires bridge_bin"))?;
    let amp_bin = opts
        .backend_bin
        .ok_or_else(|| anyhow!("amp target requires backend_bin"))?;
    let codex_home = TempDir::new().context("codex home tempdir")?;

    let mut child = Command::new(&bridge_bin)
        .env("AMP_BRIDGE_AMP_BIN", &amp_bin)
        .env("CODEX_HOME", codex_home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawn {}", bridge_bin.display()))?;

    let stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    tee_stream("amp-bridge", stderr);

    let client = JsonRpcClient::new(boxed_reader(stdout), boxed_writer(stdin));
    Ok(TargetHandle::new(
        client,
        Some(child),
        vec![codex_home],
        None,
    ))
}
