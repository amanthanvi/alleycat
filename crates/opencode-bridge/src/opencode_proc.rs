use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use alleycat_bridge_core::{
    ChildProcess, HarnessKind, HarnessLaunchReceipt, LaunchEnvironment, LaunchEnvironmentResolver,
    LocalLauncher, ProcessLauncher, ProcessRole, ProcessSpec, StdioMode, UserEnvironmentLauncher,
    probe_harness, resolve_harness_executable, shutdown_owned_child,
};
use anyhow::{Context, bail};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use url::Url;

use crate::opencode_client::OpencodeClient;

const READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(50);
const READINESS_REQUEST_TIMEOUT: Duration = Duration::from_millis(750);
const CAPABILITY_TIMEOUT: Duration = Duration::from_secs(5);
const OPENCODE_USERNAME: &str = "opencode";
const LISTENING_PREFIX: &str = "opencode server listening on ";
const STARTUP_LINE_LIMIT: usize = 8 * 1024;
const STARTUP_LINE_CHANNEL_CAPACITY: usize = 4;

enum RuntimeAuth {
    None,
    LegacyQuery(String),
    Basic { username: String, password: String },
}

struct OwnedRuntime {
    child: Mutex<Option<Box<dyn ChildProcess>>>,
    drains: Mutex<Vec<JoinHandle<()>>>,
}

pub struct OpencodeRuntime {
    pub base_url: String,
    /// Legacy externally-managed backends can still use the historical query
    /// token. Owned runtimes leave this empty and use HTTP Basic auth headers.
    pub auth_token: String,
    auth: RuntimeAuth,
    receipt: Option<HarnessLaunchReceipt>,
    owned: Option<OwnedRuntime>,
}

impl OpencodeRuntime {
    pub fn external(base_url: String, auth_token: String) -> Self {
        let auth = if auth_token.is_empty() {
            RuntimeAuth::None
        } else {
            RuntimeAuth::LegacyQuery(auth_token.clone())
        };
        Self {
            base_url,
            auth_token,
            auth,
            receipt: None,
            owned: None,
        }
    }

    pub async fn start_from_env() -> anyhow::Result<Self> {
        let cwd = std::env::current_dir().context("reading current working directory")?;
        let launch_env = LaunchEnvironmentResolver::default()
            .resolve(Some(&cwd))
            .await;

        if let Some(base_url) = env_string(&launch_env, "OPENCODE_BRIDGE_BACKEND_URL") {
            let auth_token =
                env_string(&launch_env, "OPENCODE_BRIDGE_AUTH_TOKEN").unwrap_or_default();
            return Ok(Self::external(base_url, auth_token));
        }

        reject_unsafe_owned_overrides(&launch_env)?;
        let configured_bin = std::env::var_os("OPENCODE_BRIDGE_BIN")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                env_string(&launch_env, "OPENCODE_BRIDGE_BIN")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
            });
        let executable = resolve_harness_executable(
            HarnessKind::Opencode,
            configured_bin.as_deref().or(Some(Path::new("opencode"))),
            &launch_env,
        )?;
        verify_serve_capabilities(&executable, &launch_env).await?;

        let password = random_token();
        let username = OPENCODE_USERNAME.to_string();
        let mut spec = ProcessSpec::new(executable.path.clone());
        spec.role = ProcessRole::Agent;
        spec.args = owned_server_args();
        spec.cwd = Some(cwd);
        spec.env = vec![
            (
                OsString::from("OPENCODE_SERVER_USERNAME"),
                OsString::from(&username),
            ),
            (
                OsString::from("OPENCODE_SERVER_PASSWORD"),
                OsString::from(&password),
            ),
        ];
        spec.stdin = StdioMode::Null;
        spec.stdout = StdioMode::Piped;
        spec.stderr = StdioMode::Piped;

        let local: Arc<dyn ProcessLauncher> = Arc::new(LocalLauncher);
        let launcher = UserEnvironmentLauncher::new(local);
        let mut child = launcher
            .launch(spec)
            .await
            .context("starting owned opencode server")?;
        let receipt = child.launch_receipt().cloned();
        let stdout = child
            .take_stdout()
            .context("owned opencode server did not expose stdout")?;
        let stderr = child
            .take_stderr()
            .context("owned opencode server did not expose stderr")?;
        let (line_tx, mut line_rx) = mpsc::channel(STARTUP_LINE_CHANNEL_CAPACITY);
        let drains = vec![
            tokio::spawn(drain_startup_output(stdout, line_tx.clone())),
            tokio::spawn(drain_startup_output(stderr, line_tx)),
        ];

        let base_url = match wait_for_listening(&mut child, &mut line_rx, READINESS_TIMEOUT).await {
            Ok(base_url) => base_url,
            Err(error) => {
                cleanup_failed_start(child, drains).await;
                return Err(error);
            }
        };
        let client =
            OpencodeClient::new_basic(base_url.clone(), username.clone(), password.clone());
        if let Err(error) = wait_until_healthy(&client, READINESS_TIMEOUT).await {
            cleanup_failed_start(child, drains).await;
            return Err(error);
        }

        Ok(Self {
            base_url,
            auth_token: String::new(),
            auth: RuntimeAuth::Basic { username, password },
            receipt,
            owned: Some(OwnedRuntime {
                child: Mutex::new(Some(child)),
                drains: Mutex::new(drains),
            }),
        })
    }

    pub fn launch_receipt(&self) -> Option<&HarnessLaunchReceipt> {
        self.receipt.as_ref()
    }

    pub fn is_owned(&self) -> bool {
        self.owned.is_some()
    }

    pub(crate) fn client(&self) -> OpencodeClient {
        match &self.auth {
            RuntimeAuth::None => OpencodeClient::new(self.base_url.clone(), String::new()),
            RuntimeAuth::LegacyQuery(token) => {
                OpencodeClient::new(self.base_url.clone(), token.clone())
            }
            RuntimeAuth::Basic { username, password } => {
                OpencodeClient::new_basic(self.base_url.clone(), username.clone(), password.clone())
            }
        }
    }

    pub async fn shutdown(&self) {
        let Some(owned) = &self.owned else {
            return;
        };
        if let Some(child) = owned.child.lock().await.take() {
            // OpenCode has no stdin control channel in serve mode. SIGTERM to
            // the dedicated process group is its graceful shutdown request.
            let _ = shutdown_owned_child(child, Duration::ZERO, Duration::from_secs(2)).await;
        }
        for task in owned.drains.lock().await.drain(..) {
            task.abort();
        }
    }
}

fn owned_server_args() -> Vec<OsString> {
    vec![
        OsString::from("serve"),
        OsString::from("--hostname=127.0.0.1"),
        OsString::from("--port=0"),
        OsString::from("--no-mdns"),
    ]
}

fn reject_unsafe_owned_overrides(env: &LaunchEnvironment) -> anyhow::Result<()> {
    if let Some(value) = env_string(env, "OPENCODE_BRIDGE_PORT")
        && value != "auto"
    {
        bail!(
            "OPENCODE_BRIDGE_PORT is not supported for an owned runtime; Remora Link requires loopback port 0"
        );
    }
    if env_string(env, "OPENCODE_BRIDGE_EXTRA_ARGS").is_some() {
        bail!(
            "OPENCODE_BRIDGE_EXTRA_ARGS is not supported for an owned runtime because network and discovery arguments are security-owned"
        );
    }
    if env_string(env, "OPENCODE_BRIDGE_AUTH_TOKEN").is_some() {
        bail!(
            "OPENCODE_BRIDGE_AUTH_TOKEN applies only to OPENCODE_BRIDGE_BACKEND_URL; owned runtimes generate a fresh password"
        );
    }
    Ok(())
}

async fn verify_serve_capabilities(
    executable: &alleycat_bridge_core::ResolvedExecutable,
    env: &LaunchEnvironment,
) -> anyhow::Result<()> {
    let output = probe_harness(
        executable,
        [OsString::from("serve"), OsString::from("--help")],
        env,
        CAPABILITY_TIMEOUT,
    )
    .await
    .context("probing opencode serve capabilities")?;
    let help = output.text();
    for flag in ["--hostname", "--port", "--mdns"] {
        if !help.contains(flag) {
            bail!("installed opencode does not advertise required `{flag}` serve capability");
        }
    }
    Ok(())
}

async fn drain_startup_output(mut stream: impl AsyncRead + Unpin, lines: mpsc::Sender<String>) {
    let mut read_buffer = [0u8; 4096];
    let mut line = Vec::with_capacity(256);
    let mut overflowed = false;
    let mut forward_candidates = true;

    loop {
        let Ok(read) = stream.read(&mut read_buffer).await else {
            return;
        };
        if read == 0 {
            if !overflowed && !line.is_empty() {
                forward_startup_candidate(&line, &lines, &mut forward_candidates);
            }
            return;
        }
        for byte in &read_buffer[..read] {
            if *byte == b'\n' {
                if !overflowed {
                    forward_startup_candidate(&line, &lines, &mut forward_candidates);
                }
                line.clear();
                overflowed = false;
            } else if line.len() < STARTUP_LINE_LIMIT {
                line.push(*byte);
            } else {
                // Discard the rest of an oversized line while continuing to
                // drain the pipe. No harness-controlled line can grow memory.
                overflowed = true;
            }
        }
    }
}

fn forward_startup_candidate(
    bytes: &[u8],
    lines: &mpsc::Sender<String>,
    forward_candidates: &mut bool,
) {
    if !*forward_candidates {
        return;
    }
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    let line = String::from_utf8_lossy(bytes);
    if !line.contains(LISTENING_PREFIX) {
        return;
    }
    match lines.try_send(line.into_owned()) {
        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
        Err(mpsc::error::TrySendError::Closed(_)) => *forward_candidates = false,
    }
}

async fn wait_for_listening(
    child: &mut Box<dyn ChildProcess>,
    lines: &mut mpsc::Receiver<String>,
    timeout: Duration,
) -> anyhow::Result<String> {
    tokio::time::timeout(timeout, async {
        loop {
            if let Some(status) = child.try_wait()? {
                bail!("opencode exited before reporting readiness: {status}");
            }
            tokio::select! {
                line = lines.recv() => match line {
                    Some(line) => {
                        if let Some(base_url) = parse_listening_url(&line)? {
                            return Ok(base_url);
                        }
                    }
                    None => bail!("opencode closed startup output before reporting readiness"),
                },
                _ = tokio::time::sleep(READINESS_POLL_INTERVAL) => {}
            }
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!("opencode did not report a loopback listener within {timeout:?}")
    })?
}

fn parse_listening_url(line: &str) -> anyhow::Result<Option<String>> {
    let Some(index) = line.find(LISTENING_PREFIX) else {
        return Ok(None);
    };
    let raw = line[index + LISTENING_PREFIX.len()..].trim();
    let url = Url::parse(raw).context("parsing opencode listening URL")?;
    if url.scheme() != "http" || url.host_str() != Some("127.0.0.1") {
        bail!("opencode reported a non-loopback listener; refusing to connect");
    }
    let port = url
        .port()
        .context("opencode listening URL did not include an assigned port")?;
    if port == 0 {
        bail!("opencode reported unassigned port 0 as ready");
    }
    Ok(Some(format!("http://127.0.0.1:{port}")))
}

async fn wait_until_healthy(client: &OpencodeClient, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let healthy = tokio::time::timeout(READINESS_REQUEST_TIMEOUT, client.get("/global/health"))
            .await
            .ok()
            .and_then(Result::ok)
            .and_then(|body| body.get("healthy").and_then(serde_json::Value::as_bool))
            == Some(true);
        if healthy {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("opencode did not report healthy within {timeout:?}");
        }
        tokio::time::sleep(READINESS_POLL_INTERVAL).await;
    }
}

async fn cleanup_failed_start(child: Box<dyn ChildProcess>, drains: Vec<JoinHandle<()>>) {
    let _ = shutdown_owned_child(child, Duration::ZERO, Duration::from_secs(1)).await;
    for task in drains {
        task.abort();
    }
}

fn env_string(env: &LaunchEnvironment, key: &str) -> Option<String> {
    env.get(key)
        .and_then(OsStr::to_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn external_constructor_stores_fields_and_spawns_no_child() {
        let runtime = OpencodeRuntime::external(
            "http://example.test:1234".to_string(),
            "tok-abc".to_string(),
        );
        assert_eq!(runtime.base_url, "http://example.test:1234");
        assert_eq!(runtime.auth_token, "tok-abc");
        assert!(!runtime.is_owned());
    }

    #[test]
    fn owned_args_pin_loopback_ephemeral_port_and_disable_mdns() {
        assert_eq!(
            owned_server_args(),
            ["serve", "--hostname=127.0.0.1", "--port=0", "--no-mdns"].map(OsString::from)
        );
    }

    #[test]
    fn listening_parser_accepts_only_assigned_ipv4_loopback() {
        assert_eq!(
            parse_listening_url("opencode server listening on http://127.0.0.1:4096").unwrap(),
            Some("http://127.0.0.1:4096".into())
        );
        assert!(parse_listening_url("opencode server listening on http://0.0.0.0:4096").is_err());
        assert!(parse_listening_url("diagnostic message").unwrap().is_none());
    }

    #[test]
    fn generated_passwords_are_high_entropy_and_unique() {
        let first = random_token();
        let second = random_token();
        assert_eq!(first.len(), 64);
        assert_eq!(second.len(), 64);
        assert_ne!(first, second);
        assert!(first.chars().all(|character| character.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn startup_drain_discards_oversized_lines_and_forwards_only_readiness() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let (tx, mut rx) = mpsc::channel(STARTUP_LINE_CHANNEL_CAPACITY);
        let drain = tokio::spawn(drain_startup_output(reader, tx));
        let write = tokio::spawn(async move {
            writer
                .write_all(&vec![b'x'; STARTUP_LINE_LIMIT + 1024])
                .await
                .unwrap();
            writer.write_all(b"\nignored diagnostic\n").await.unwrap();
            writer
                .write_all(b"opencode server listening on http://127.0.0.1:4096\n")
                .await
                .unwrap();
        });

        let line = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("readiness timeout")
            .expect("readiness line");
        assert_eq!(line, "opencode server listening on http://127.0.0.1:4096");
        write.await.unwrap();
        drain.await.unwrap();
        assert!(rx.try_recv().is_err());
    }
}
