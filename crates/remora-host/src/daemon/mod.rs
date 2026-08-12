//! Long-running daemon process for `remora-link serve`.
//!
//! Owns the single-instance file lock, the persistent iroh secret + token,
//! the iroh endpoint serving agent streams, and the IPC control listener
//! used by the CLI subcommands (`status`/`pair`/`reload`/`stop`/
//! `agents`).

pub mod control;
pub mod logging;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use arc_swap::ArcSwap;
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;

use crate::agents::AgentManager;
use crate::config::HostConfig;
use crate::framing::{read_json_frame, write_json_frame};
use crate::host;
use crate::ipc::{ControlListener, ControlStream};
use crate::paths;
use crate::state;

use self::control::{
    DeviceRevokeResult, PairingApprovalResult, PairingApprovalScope, PairingRejectionResult,
    PairingResultV2, Request, Response, StatusInfo,
};

/// Entry point for `remora-link serve`. Initializes file logging, acquires the
/// single-instance lock, binds the iroh endpoint + control IPC, and runs
/// until SIGTERM / SIGINT / control `Stop`.
pub async fn run() -> anyhow::Result<()> {
    let log_dir = paths::log_dir().context("locating log directory")?;
    let _log_guard: WorkerGuard =
        logging::init("info", &log_dir).context("initializing logging")?;

    let mut lock = state::acquire_lock().await.context("acquiring lock file")?;
    let _lock_guard = lock.try_write().map_err(|_| {
        let pid_hint = state::read_pid_file().unwrap_or(None);
        let name = crate::binary_name();
        match pid_hint {
            Some(pid) => anyhow!(
                "another {name} daemon is already running (pid {pid}). use `{name} stop` first."
            ),
            None => {
                anyhow!("another {name} daemon is already running. use `{name} stop` first.")
            }
        }
    })?;

    let pid_path = state::write_pid_file().context("writing pid file")?;
    let _pid_cleanup = RemoveOnDrop(pid_path);

    let initial_config = crate::config::load_or_init()
        .await
        .context("loading host config")?;
    let config = Arc::new(ArcSwap::from_pointee(initial_config));

    let secret_key = state::load_or_create_secret_key()
        .await
        .context("loading host secret key")?;
    let node_id = secret_key.public().to_string();
    info!(node_id = %node_id, "loaded persistent identity");

    let pairing = crate::pairing_v2::PairingManager::load_default()
        .await
        .context("loading Remora Link device grants")?;
    let catalog = Arc::new(
        crate::catalog::HostCatalogStore::open_default()
            .context("loading command-center Host catalog")?,
    );
    info!(host_id = %catalog.snapshot().host_id.as_str(), "loaded command-center catalog");

    let endpoint = host::bind_endpoint(secret_key.clone()).await?;
    let agents = AgentManager::new(Arc::clone(&config))
        .await
        .context("initializing agent manager")?;

    let started_at = Instant::now();
    let shutdown = Arc::new(Notify::new());

    let serve_task = {
        let endpoint = endpoint.clone();
        let agents = agents.clone();
        let pairing = pairing.clone();
        let catalog = Arc::clone(&catalog);
        let shutdown = Arc::clone(&shutdown);
        tokio::spawn(async move {
            if let Err(error) =
                host::accept_loop(endpoint, agents, pairing, catalog, shutdown).await
            {
                error!("iroh accept loop ended: {error:#}");
            }
        })
    };

    let listener = ControlListener::bind()
        .await
        .context("binding control listener")?;
    info!("control socket listening");

    let daemon = Arc::new(DaemonState {
        config: Arc::clone(&config),
        agents,
        endpoint: endpoint.clone(),
        node_id,
        pairing,
        catalog,
        started_at,
        shutdown: Arc::clone(&shutdown),
    });

    let accept_task = tokio::spawn(accept_loop(Arc::clone(&daemon), listener));

    wait_for_signal(Arc::clone(&shutdown)).await;
    info!("shutdown initiated");

    accept_task.abort();
    let _ = accept_task.await;

    let serve_abort = serve_task.abort_handle();
    match tokio::time::timeout(std::time::Duration::from_secs(5), serve_task).await {
        Ok(_) => {}
        Err(_) => {
            warn!("iroh shutdown did not complete within 5s; aborting");
            serve_abort.abort();
        }
    }

    // Kill agent child processes (ACP, claude, …) deterministically.
    // Without this, only tokio's `kill_on_drop` keeps them honest, and
    // that's racy on process exit — between restarts we'd accumulate
    // orphaned `devin acp` / `grok agent stdio` children until manual `pkill`.
    info!("shutting down bridges");
    daemon.agents.shutdown().await;

    info!("daemon exited cleanly");
    Ok(())
}

struct DaemonState {
    config: Arc<ArcSwap<HostConfig>>,
    agents: AgentManager,
    endpoint: iroh::Endpoint,
    node_id: String,
    pairing: crate::pairing_v2::PairingManager,
    catalog: Arc<crate::catalog::HostCatalogStore>,
    started_at: Instant,
    shutdown: Arc<Notify>,
}

async fn accept_loop(daemon: Arc<DaemonState>, mut listener: ControlListener) {
    loop {
        match listener.accept().await {
            Ok(stream) => {
                let daemon = Arc::clone(&daemon);
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(daemon, stream).await {
                        debug!("control connection ended: {error:#}");
                    }
                });
            }
            Err(error) => {
                warn!("control accept error: {error:#}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_connection(
    daemon: Arc<DaemonState>,
    mut stream: Box<dyn ControlStream>,
) -> anyhow::Result<()> {
    let request: Request = read_json_frame(&mut stream)
        .await
        .context("reading request")?;
    debug!(operation = request.operation_name(), "control request");
    let (response, after) = dispatch(Arc::clone(&daemon), request).await;
    write_json_frame(&mut stream, &response)
        .await
        .context("writing response")?;
    drop(stream);
    if let Some(PostResponse::Shutdown) = after {
        daemon.shutdown.notify_waiters();
    }
    Ok(())
}

enum PostResponse {
    Shutdown,
}

async fn dispatch(daemon: Arc<DaemonState>, request: Request) -> (Response, Option<PostResponse>) {
    match request {
        Request::Status => (handle_status(&daemon).await, None),
        Request::Pair {
            runtime_ids,
            allow_restart,
            unattended,
            ttl_secs,
        } => (
            handle_pair(&daemon, runtime_ids, allow_restart, unattended, ttl_secs).await,
            None,
        ),
        Request::Reload => (handle_reload(&daemon).await, None),
        Request::AgentsList => (handle_agents_list(&daemon).await, None),
        Request::DevicesList => (handle_devices_list(&daemon).await, None),
        Request::DeviceRevoke { device_id } => {
            (handle_device_revoke(&daemon, &device_id).await, None)
        }
        Request::PairingsPending => (handle_pairings_pending(&daemon).await, None),
        Request::PairingApprove {
            claim_id,
            runtime_ids,
            scopes,
        } => (
            handle_pairing_approve(&daemon, &claim_id, runtime_ids, scopes).await,
            None,
        ),
        Request::PairingReject { claim_id } => {
            (handle_pairing_reject(&daemon, &claim_id).await, None)
        }
        Request::Stop => (Response::ok(), Some(PostResponse::Shutdown)),
    }
}

async fn handle_status(daemon: &DaemonState) -> Response {
    let cfg = daemon.config.load();
    let catalog = daemon.catalog.snapshot();
    let info = StatusInfo {
        pid: std::process::id(),
        node_id: daemon.node_id.clone(),
        relay: host::endpoint_home_relay(Some(&daemon.endpoint)).or_else(|| cfg.relay.clone()),
        config_path: paths::host_config_file()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string()),
        uptime_secs: daemon.started_at.elapsed().as_secs(),
        agents: daemon.agents.list_agents().await,
        version: Some(crate::binary_version().to_string()),
        host_id: Some(catalog.host_id.0),
        catalog_generation: Some(catalog.generation),
    };
    Response::ok_with(&info).unwrap_or_else(|e| Response::err(e.to_string()))
}

async fn handle_pair(
    daemon: &DaemonState,
    runtime_ids: Vec<String>,
    allow_restart: bool,
    unattended: bool,
    ttl_secs: Option<u64>,
) -> Response {
    if let Err(error) =
        validate_pair_policy(daemon, &runtime_ids, allow_restart, unattended, ttl_secs)
    {
        return Response::err(error.to_string());
    }
    wait_for_relay(&daemon.endpoint).await;
    let cfg = daemon.config.load();
    let relay = host::endpoint_home_relay(Some(&daemon.endpoint)).or_else(|| cfg.relay.clone());
    drop(cfg);
    let mut options = if unattended {
        crate::pairing_v2::InvitationOptions::unattended(runtime_ids[0].clone())
    } else {
        crate::pairing_v2::InvitationOptions::interactive(runtime_ids.clone(), allow_restart)
    };
    if let Some(ttl_secs) = ttl_secs {
        options.ttl = Duration::from_secs(ttl_secs);
    }
    let invitation = match daemon
        .pairing
        .create_invitation(
            daemon.node_id.clone(),
            host::local_host_name(),
            relay,
            options,
        )
        .await
    {
        Ok(invitation) => invitation,
        Err(error) => return Response::err(format!("creating pairing invitation: {error:#}")),
    };
    let code = match invitation.to_pairing_code() {
        Ok(code) => code,
        Err(error) => return Response::err(format!("encoding pairing invitation: {error:#}")),
    };
    Response::ok_with(&PairingResultV2 { invitation, code })
        .unwrap_or_else(|error| Response::err(error.to_string()))
}

fn validate_pair_policy(
    daemon: &DaemonState,
    runtime_ids: &[String],
    allow_restart: bool,
    unattended: bool,
    ttl_secs: Option<u64>,
) -> anyhow::Result<()> {
    anyhow::ensure!(!runtime_ids.is_empty(), "at least one runtime is required");
    anyhow::ensure!(runtime_ids.len() <= 16, "at most 16 runtimes are allowed");
    let mut unique = std::collections::BTreeSet::new();
    for runtime in runtime_ids {
        anyhow::ensure!(
            runtime.len() <= 64
                && !runtime.is_empty()
                && runtime
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "invalid runtime ID"
        );
        anyhow::ensure!(unique.insert(runtime), "duplicate runtime ID");
        anyhow::ensure!(
            AgentManager::agent_id(runtime).is_some() && daemon.agents.agent_enabled(runtime),
            "runtime '{runtime}' is unknown or disabled"
        );
    }
    if unattended {
        anyhow::ensure!(
            runtime_ids.len() == 1,
            "unattended pairing requires exactly one runtime"
        );
        anyhow::ensure!(!allow_restart, "unattended pairing cannot allow restart");
        anyhow::ensure!(
            ttl_secs.is_none_or(|ttl| ttl <= 60),
            "unattended pairing TTL cannot exceed 60 seconds"
        );
    } else {
        anyhow::ensure!(
            ttl_secs
                .is_none_or(|ttl| { ttl <= crate::pairing_v2::DEFAULT_INVITATION_TTL.as_secs() }),
            "interactive pairing TTL cannot exceed 300 seconds"
        );
    }
    anyhow::ensure!(
        ttl_secs.is_none_or(|ttl| ttl > 0),
        "pairing TTL must be positive"
    );
    Ok(())
}

/// Best-effort wait for the iroh endpoint to bind a home relay before
/// serializing a pair payload. Without this, a freshly-spawned daemon will
/// happily emit a QR with `relay: null` because the relay-probe task hasn't
/// completed yet — and on networks where pkarr/DNS publishing is broken
/// (Tailscale, IPv6-only relays), that QR is undialable. 8s matches the
/// existing online-probe timeout in `host::bind_endpoint`. If the network
/// truly has no relay path, we fall through and emit whatever we have.
async fn wait_for_relay(endpoint: &iroh::Endpoint) {
    let _ = tokio::time::timeout(std::time::Duration::from_secs(8), endpoint.online()).await;
}

async fn handle_reload(daemon: &DaemonState) -> Response {
    let new_cfg = match crate::config::load_or_init().await {
        Ok(c) => c,
        Err(error) => return Response::err(format!("loading config: {error:#}")),
    };
    daemon.config.store(Arc::new(new_cfg));
    Response::ok()
}

async fn handle_agents_list(daemon: &DaemonState) -> Response {
    let agents = daemon.agents.list_agents().await;
    Response::ok_with(&agents).unwrap_or_else(|e| Response::err(e.to_string()))
}

async fn handle_devices_list(daemon: &DaemonState) -> Response {
    Response::ok_with(&daemon.pairing.list_devices().await)
        .unwrap_or_else(|error| Response::err(error.to_string()))
}

async fn handle_device_revoke(daemon: &DaemonState, device_id: &str) -> Response {
    match daemon.pairing.revoke_device(device_id).await {
        Ok(Some(device)) => Response::ok_with(&DeviceRevokeResult { device })
            .unwrap_or_else(|error| Response::err(error.to_string())),
        Ok(None) => Response::err("device not found"),
        Err(error) => Response::err(format!("revoking device: {error:#}")),
    }
}

async fn handle_pairings_pending(daemon: &DaemonState) -> Response {
    Response::ok_with(&daemon.pairing.list_pending().await)
        .unwrap_or_else(|error| Response::err(error.to_string()))
}

async fn handle_pairing_approve(
    daemon: &DaemonState,
    claim_id: &str,
    runtime_ids: Option<Vec<String>>,
    scopes: Option<Vec<PairingApprovalScope>>,
) -> Response {
    let Some(pending) = daemon.pairing.pairing_claim_summary(claim_id).await else {
        return Response::err("pending pairing claim not found");
    };

    let runtime_ids = runtime_ids.unwrap_or(pending.selected_runtime_ids);
    let granted_scopes = match scopes {
        Some(scopes) => {
            let mut seen = std::collections::BTreeSet::new();
            if !scopes.iter().all(|scope| seen.insert(*scope)) {
                return Response::err("duplicate pairing approval scope");
            }
            let mut granted: Vec<_> = scopes.into_iter().map(device_scope).collect();
            granted.push(crate::pairing_v2::DeviceScopeV2::SelfRevoke);
            granted
        }
        None => pending.requested_scopes,
    };

    match daemon
        .pairing
        .approve_pending(claim_id, &runtime_ids, &granted_scopes)
        .await
    {
        Ok(Some(device)) => Response::ok_with(&PairingApprovalResult {
            device: crate::pairing_v2::DeviceSummary {
                device_id: device.device_id,
                display_name: device.display_name,
                endpoint_fingerprint: device.endpoint_fingerprint,
                device_key_fingerprint: device.device_key_fingerprint,
                selected_runtime_ids: device.selected_runtime_ids,
                granted_scopes: device.granted_scopes,
                auth_epoch: device.auth_epoch,
                state: crate::pairing_v2::GrantStateV2::Active,
                created_at: device.created_at,
                revoked_at: None,
            },
        })
        .unwrap_or_else(|error| Response::err(error.to_string())),
        Ok(None) => Response::err("pending pairing claim not found"),
        Err(error) => Response::err(format!("approving pairing claim: {error:#}")),
    }
}

async fn handle_pairing_reject(daemon: &DaemonState, claim_id: &str) -> Response {
    match daemon.pairing.reject_pending(claim_id).await {
        Ok(rejected) => Response::ok_with(&PairingRejectionResult {
            claim_id: claim_id.to_string(),
            rejected,
        })
        .unwrap_or_else(|error| Response::err(error.to_string())),
        Err(error) => Response::err(format!("rejecting pairing claim: {error:#}")),
    }
}

fn device_scope(scope: PairingApprovalScope) -> crate::pairing_v2::DeviceScopeV2 {
    match scope {
        PairingApprovalScope::Inspect => crate::pairing_v2::DeviceScopeV2::InspectRuntimes,
        PairingApprovalScope::Connect => crate::pairing_v2::DeviceScopeV2::ConnectRuntime,
        PairingApprovalScope::Restart => crate::pairing_v2::DeviceScopeV2::RestartRuntime,
    }
}

async fn wait_for_signal(shutdown: Arc<Notify>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = term.recv() => info!("received SIGTERM"),
            _ = int.recv() => info!("received SIGINT"),
            _ = shutdown.notified() => info!("received Stop request"),
        }
    }
    #[cfg(windows)]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => info!("received Ctrl-C"),
            _ = shutdown.notified() => info!("received Stop request"),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        shutdown.notified().await;
    }
    // Fan the shutdown notification out to other tasks (notably the iroh
    // accept loop, which is also parked on this Notify). Idempotent — if
    // we returned because of a Stop request the IPC handler already called
    // notify_waiters(); calling it again here just sees an empty wait list.
    shutdown.notify_waiters();
}

struct RemoveOnDrop(PathBuf);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
