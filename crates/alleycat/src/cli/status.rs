use clap::Args;

use crate::agents::AgentManager;
use crate::cli;
use crate::daemon::control::{Request, StatusInfo, token_fingerprint};
use crate::ipc;
use crate::paths;
use crate::protocol::AgentInfo;

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Emit machine-readable JSON instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

pub async fn run(args: StatusArgs) -> anyhow::Result<()> {
    let info = status_info().await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }

    println!("{} daemon", crate::binary_name());
    println!("  pid:               {}", info.pid);
    println!(
        "  version:           {}",
        info.version.as_deref().unwrap_or("<unknown>")
    );
    println!("  node id:           {}", info.node_id);
    println!("  token (sha256/16): {}", info.token_short);
    println!(
        "  relay:             {}",
        info.relay.as_deref().unwrap_or("<iroh default>")
    );
    println!("  config:            {}", info.config_path);
    if info.uptime_secs > 0 {
        println!("  uptime (s):        {}", info.uptime_secs);
    } else {
        println!("  uptime (s):        <daemon not running>");
    }
    println!("  agents:");
    for agent in &info.agents {
        println!(
            "    {} display=\"{}\" wire={} available={}",
            agent.name,
            agent.display_name,
            agent.wire.as_str(),
            agent.available
        );
    }
    Ok(())
}

async fn status_info() -> anyhow::Result<StatusInfo> {
    if ipc::is_daemon_running().await {
        let resp = cli::send(Request::Status).await?;
        cli::decode_data::<StatusInfo>(resp)
    } else {
        offline_status().await
    }
}

/// Status when the daemon isn't running. Pid is 0 and uptime is 0 so the
/// human renderer can call out the offline state.
async fn offline_status() -> anyhow::Result<StatusInfo> {
    let cfg = crate::config::load_existing().await.map_err(|error| {
        anyhow::anyhow!(
            "{} is not initialized; start the daemon before requesting status: {error:#}",
            crate::binary_name()
        )
    })?;
    let secret_key = crate::state::load_existing_secret_key().await?;
    let agent_list: Vec<AgentInfo> = AgentManager::offline_agent_summaries();
    Ok(StatusInfo {
        pid: 0,
        node_id: secret_key.public().to_string(),
        token_short: token_fingerprint(&cfg.token),
        relay: cfg.relay.clone(),
        config_path: paths::existing_host_config_file()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string()),
        uptime_secs: 0,
        agents: agent_list,
        version: Some(crate::binary_version().to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempHome;

    #[tokio::test]
    async fn status_entry_path_fails_without_creating_host_or_control_state() {
        let mut home = TempHome::new();
        let tmp = home.path().to_string_lossy().into_owned();
        home.override_env(&[("TMPDIR", &tmp), ("XDG_RUNTIME_DIR", "")]);

        let error = status_info().await.unwrap_err().to_string();
        assert!(error.contains("not initialized"));
        assert!(
            std::fs::read_dir(home.path()).unwrap().next().is_none(),
            "read-only status created files under {}",
            home.path().display()
        );
    }
}
