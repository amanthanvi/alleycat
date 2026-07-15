//! Shared coding-harness discovery and probe contracts.
//!
//! Detection is deliberately passive: it checks configured files, the
//! already-resolved user `PATH`, and a small ordered set of trusted install
//! locations. It never invokes a package manager, installer, shell profile,
//! or harness login command.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::time::Instant;

use crate::launch_environment::LaunchEnvironment;
use crate::launcher::{LocalLauncher, ProcessLauncher, ProcessRole, ProcessSpec, StdioMode};

pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const MAX_PROBE_OUTPUT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessKind {
    Codex,
    Claude,
    Opencode,
    Pi,
}

impl HarnessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Opencode => "opencode",
            Self::Pi => "pi",
        }
    }

    pub fn from_program(program: &Path) -> Option<Self> {
        let name = program.file_name()?.to_str()?.to_ascii_lowercase();
        let name = name
            .strip_suffix(".exe")
            .or_else(|| name.strip_suffix(".cmd"))
            .or_else(|| name.strip_suffix(".bat"))
            .unwrap_or(&name);
        match name {
            "codex" => Some(Self::Codex),
            "claude" => Some(Self::Claude),
            "opencode" => Some(Self::Opencode),
            "pi" | "pi-coding-agent" => Some(Self::Pi),
            _ => None,
        }
    }

    fn path_names(self) -> &'static [&'static str] {
        match self {
            Self::Codex => &["codex"],
            Self::Claude => &["claude"],
            Self::Opencode => &["opencode"],
            Self::Pi => &["pi", "pi-coding-agent"],
        }
    }
}

impl std::fmt::Display for HarnessKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableSource {
    ConfiguredAbsolute,
    UserPath,
    TrustedLocation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedExecutable {
    pub harness: HarnessKind,
    pub path: PathBuf,
    pub source: ExecutableSource,
}

#[derive(Debug, Error)]
pub enum ResolveExecutableError {
    #[error("configured {harness} executable must be an absolute path, got {path}")]
    RelativeConfiguredPath { harness: HarnessKind, path: PathBuf },

    #[error("configured {harness} executable is not an executable file: {path}")]
    ConfiguredNotExecutable { harness: HarnessKind, path: PathBuf },

    #[error("{harness} executable was not found on the user PATH or in trusted locations")]
    NotFound { harness: HarnessKind },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessAuthState {
    /// Installation/version probes do not establish account authentication.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkingDirectoryTrust {
    NotApplicable,
    ValidatedLocal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessLaunchReceipt {
    pub harness: HarnessKind,
    pub executable: PathBuf,
    pub source: ExecutableSource,
    pub version: Option<String>,
    pub pid: Option<u32>,
    pub cwd: Option<PathBuf>,
    pub cwd_trust: WorkingDirectoryTrust,
    pub auth_state: HarnessAuthState,
}

#[derive(Debug, Clone)]
pub struct ProbeOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub output_truncated: bool,
}

impl ProbeOutput {
    pub fn text(&self) -> String {
        let mut text = String::from_utf8_lossy(&self.stdout).into_owned();
        if !self.stderr.is_empty() {
            text.push('\n');
            text.push_str(&String::from_utf8_lossy(&self.stderr));
        }
        text
    }
}

#[derive(Debug, Error)]
pub enum HarnessProbeError {
    #[error("failed to start {harness} capability probe: {source}")]
    Spawn {
        harness: HarnessKind,
        #[source]
        source: std::io::Error,
    },

    #[error("{harness} capability probe timed out after {timeout:?}")]
    Timeout {
        harness: HarnessKind,
        timeout: Duration,
    },

    #[error("{harness} capability probe exited unsuccessfully with {status}")]
    Unsuccessful {
        harness: HarnessKind,
        status: ExitStatus,
    },

    #[error("failed to read {harness} capability probe output: {source}")]
    Output {
        harness: HarnessKind,
        #[source]
        source: std::io::Error,
    },
}

/// Resolve in a stable, security-relevant order:
///
/// 1. an explicitly configured absolute executable;
/// 2. the first matching executable in the resolved user `PATH`;
/// 3. ordered, product-owned trusted locations.
///
/// A relative configured path containing directory components is rejected.
/// A bare configured name is treated as the preferred `PATH` name, which
/// keeps existing `bin = "claude"` style host configuration working.
pub fn resolve_harness_executable(
    harness: HarnessKind,
    configured: Option<&Path>,
    env: &LaunchEnvironment,
) -> Result<ResolvedExecutable, ResolveExecutableError> {
    if let Some(path) = configured.filter(|path| path.is_absolute()) {
        return canonical_executable(path)
            .map(|path| ResolvedExecutable {
                harness,
                path,
                source: ExecutableSource::ConfiguredAbsolute,
            })
            .ok_or_else(|| ResolveExecutableError::ConfiguredNotExecutable {
                harness,
                path: path.to_path_buf(),
            });
    }

    if let Some(path) = configured
        && path.components().count() > 1
    {
        return Err(ResolveExecutableError::RelativeConfiguredPath {
            harness,
            path: path.to_path_buf(),
        });
    }

    let mut path_names = Vec::new();
    if let Some(name) = configured
        .and_then(Path::to_str)
        .filter(|name| !name.is_empty())
    {
        path_names.push(name.to_string());
    }
    for name in harness.path_names() {
        if !path_names.iter().any(|candidate| candidate == name) {
            path_names.push((*name).to_string());
        }
    }

    for name in &path_names {
        if let Some(path) = env
            .find_on_path(name)
            .and_then(|path| canonical_executable(&path))
        {
            return Ok(ResolvedExecutable {
                harness,
                path,
                source: ExecutableSource::UserPath,
            });
        }
    }

    for path in trusted_locations(harness, env) {
        if let Some(path) = canonical_executable(&path) {
            return Ok(ResolvedExecutable {
                harness,
                path,
                source: ExecutableSource::TrustedLocation,
            });
        }
    }

    Err(ResolveExecutableError::NotFound { harness })
}

pub fn ordered_harness_candidates(
    harness: HarnessKind,
    configured: Option<&Path>,
    env: &LaunchEnvironment,
) -> Result<Vec<ResolvedExecutable>, ResolveExecutableError> {
    if let Some(path) = configured.filter(|path| path.is_absolute()) {
        let path = canonical_executable(path).ok_or_else(|| {
            ResolveExecutableError::ConfiguredNotExecutable {
                harness,
                path: path.to_path_buf(),
            }
        })?;
        return Ok(vec![ResolvedExecutable {
            harness,
            path,
            source: ExecutableSource::ConfiguredAbsolute,
        }]);
    }
    if let Some(path) = configured
        && path.components().count() > 1
    {
        return Err(ResolveExecutableError::RelativeConfiguredPath {
            harness,
            path: path.to_path_buf(),
        });
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut names = Vec::new();
    if let Some(name) = configured
        .and_then(Path::to_str)
        .filter(|name| !name.is_empty())
    {
        names.push(name.to_string());
    }
    for name in harness.path_names() {
        if !names.iter().any(|candidate| candidate == name) {
            names.push((*name).to_string());
        }
    }
    for name in &names {
        if let Some(path) = env
            .find_on_path(name)
            .and_then(|path| canonical_executable(&path))
            && seen.insert(path.clone())
        {
            out.push(ResolvedExecutable {
                harness,
                path,
                source: ExecutableSource::UserPath,
            });
        }
    }
    for path in trusted_locations(harness, env) {
        if let Some(path) = canonical_executable(&path)
            && seen.insert(path.clone())
        {
            out.push(ResolvedExecutable {
                harness,
                path,
                source: ExecutableSource::TrustedLocation,
            });
        }
    }
    if out.is_empty() {
        Err(ResolveExecutableError::NotFound { harness })
    } else {
        Ok(out)
    }
}

pub async fn probe_harness(
    executable: &ResolvedExecutable,
    args: impl IntoIterator<Item = OsString>,
    env: &LaunchEnvironment,
    timeout: Duration,
) -> Result<ProbeOutput, HarnessProbeError> {
    let deadline = Instant::now() + timeout;
    let mut spec = ProcessSpec::new(executable.path.clone());
    spec.role = ProcessRole::Probe;
    spec.args = args.into_iter().collect();
    spec.env = env.clone().into_pairs();
    spec.env_clear = true;
    spec.stdin = StdioMode::Null;
    spec.stdout = StdioMode::Piped;
    spec.stderr = StdioMode::Piped;

    let mut child = tokio::time::timeout_at(deadline, LocalLauncher.launch(spec))
        .await
        .map_err(|_| HarnessProbeError::Timeout {
            harness: executable.harness,
            timeout,
        })?
        .map_err(|source| HarnessProbeError::Spawn {
            harness: executable.harness,
            source,
        })?;
    let stdout = child
        .take_stdout()
        .ok_or_else(|| HarnessProbeError::Output {
            harness: executable.harness,
            source: std::io::Error::other("probe stdout pipe was unavailable"),
        })?;
    let stderr = child
        .take_stderr()
        .ok_or_else(|| HarnessProbeError::Output {
            harness: executable.harness,
            source: std::io::Error::other("probe stderr pipe was unavailable"),
        })?;

    let mut stdout_task = tokio::spawn(read_bounded(stdout));
    let mut stderr_task = tokio::spawn(read_bounded(stderr));
    let status = match tokio::time::timeout_at(deadline, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(source)) => {
            let _ = child.terminate_tree().await;
            let _ = child.kill_tree().await;
            stdout_task.abort();
            stderr_task.abort();
            return Err(HarnessProbeError::Output {
                harness: executable.harness,
                source,
            });
        }
        Err(_) => {
            let _ = child.terminate_tree().await;
            let _ = child.kill_tree().await;
            stdout_task.abort();
            stderr_task.abort();
            // Reap outside the caller's absolute deadline. The complete
            // process group has already received SIGKILL/job termination.
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
            return Err(HarnessProbeError::Timeout {
                harness: executable.harness,
                timeout,
            });
        }
    };

    // A short-lived root can leave descendants holding inherited pipes. Kill
    // the retained process group before joining drains, and keep those joins
    // inside the same absolute probe deadline.
    let _ = child.terminate_tree().await;
    let _ = child.kill_tree().await;
    let drains = tokio::time::timeout_at(deadline, async {
        let stdout = (&mut stdout_task).await;
        let stderr = (&mut stderr_task).await;
        (stdout, stderr)
    })
    .await;
    let (stdout_result, stderr_result) = match drains {
        Ok(results) => results,
        Err(_) => {
            stdout_task.abort();
            stderr_task.abort();
            return Err(HarnessProbeError::Timeout {
                harness: executable.harness,
                timeout,
            });
        }
    };
    let (stdout, stdout_truncated) = stdout_result
        .map_err(|source| HarnessProbeError::Output {
            harness: executable.harness,
            source: std::io::Error::other(source),
        })?
        .map_err(|source| HarnessProbeError::Output {
            harness: executable.harness,
            source,
        })?;
    let (stderr, stderr_truncated) = stderr_result
        .map_err(|source| HarnessProbeError::Output {
            harness: executable.harness,
            source: std::io::Error::other(source),
        })?
        .map_err(|source| HarnessProbeError::Output {
            harness: executable.harness,
            source,
        })?;

    if !status.success() {
        return Err(HarnessProbeError::Unsuccessful {
            harness: executable.harness,
            status,
        });
    }
    Ok(ProbeOutput {
        status,
        stdout,
        stderr,
        output_truncated: stdout_truncated || stderr_truncated,
    })
}

pub async fn probe_harness_version(
    executable: &ResolvedExecutable,
    env: &LaunchEnvironment,
) -> Result<Option<String>, HarnessProbeError> {
    let output = probe_harness(
        executable,
        [OsString::from("--version")],
        env,
        DEFAULT_PROBE_TIMEOUT,
    )
    .await?;
    Ok(output
        .text()
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| line.chars().take(256).collect()))
}

pub fn validate_local_working_directory(path: &Path) -> std::io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("working directory must be absolute: {}", path.display()),
        ));
    }
    let canonical = path.canonicalize().map_err(|source| {
        std::io::Error::new(
            source.kind(),
            format!("working directory is unavailable: {}", path.display()),
        )
    })?;
    if !canonical.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("working directory is not a directory: {}", path.display()),
        ));
    }
    Ok(canonical)
}

fn trusted_locations(harness: HarnessKind, env: &LaunchEnvironment) -> Vec<PathBuf> {
    let home = env
        .get("HOME")
        .or_else(|| env.get("USERPROFILE"))
        .map(PathBuf::from);
    let mut paths = Vec::new();

    match harness {
        HarnessKind::Codex => {
            if let Some(codex_home) = env.get("CODEX_HOME").filter(|value| !value.is_empty()) {
                paths.push(PathBuf::from(codex_home).join("packages/standalone/current/codex"));
            } else {
                push_home_candidate(
                    &mut paths,
                    home.as_deref(),
                    ".codex/packages/standalone/current/codex",
                );
            }
            push_home_candidate(&mut paths, home.as_deref(), ".local/bin/codex");
            push_home_candidate(&mut paths, home.as_deref(), ".bun/bin/codex");
            push_home_candidate(&mut paths, home.as_deref(), ".volta/bin/codex");
            push_home_candidate(&mut paths, home.as_deref(), ".cargo/bin/codex");
            #[cfg(target_os = "macos")]
            {
                push_home_candidate(
                    &mut paths,
                    home.as_deref(),
                    "Applications/Codex.app/Contents/Resources/codex",
                );
                paths.push(PathBuf::from(
                    "/Applications/Codex.app/Contents/Resources/codex",
                ));
            }
        }
        HarnessKind::Claude => {
            push_home_candidate(&mut paths, home.as_deref(), ".local/bin/claude");
            push_home_candidate(&mut paths, home.as_deref(), ".claude/local/claude");
        }
        HarnessKind::Opencode => {
            push_home_candidate(&mut paths, home.as_deref(), ".opencode/bin/opencode");
            push_home_candidate(&mut paths, home.as_deref(), ".local/bin/opencode");
        }
        HarnessKind::Pi => {
            for name in ["pi", "pi-coding-agent"] {
                push_home_candidate(&mut paths, home.as_deref(), &format!(".local/bin/{name}"));
                push_home_candidate(&mut paths, home.as_deref(), &format!(".bun/bin/{name}"));
                push_home_candidate(&mut paths, home.as_deref(), &format!(".volta/bin/{name}"));
            }
        }
    }

    #[cfg(not(windows))]
    for name in harness.path_names() {
        paths.push(PathBuf::from("/opt/homebrew/bin").join(name));
        paths.push(PathBuf::from("/usr/local/bin").join(name));
        paths.push(PathBuf::from("/usr/bin").join(name));
    }

    #[cfg(windows)]
    if let Some(home) = home {
        for name in harness.path_names() {
            paths.push(home.join("AppData/Roaming/npm").join(format!("{name}.cmd")));
            paths.push(home.join(".local/bin").join(format!("{name}.exe")));
        }
    }

    paths
}

fn push_home_candidate(paths: &mut Vec<PathBuf>, home: Option<&Path>, suffix: &str) {
    if let Some(home) = home {
        paths.push(home.join(suffix));
    }
}

fn canonical_executable(path: &Path) -> Option<PathBuf> {
    if !is_executable_file(path) {
        return None;
    }
    path.canonicalize()
        .ok()
        .or_else(|| Some(path.to_path_buf()))
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

async fn read_bounded(
    mut reader: impl tokio::io::AsyncRead + Unpin,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::new();
    let mut truncated = false;
    let mut buffer = [0u8; 4096];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = MAX_PROBE_OUTPUT_BYTES.saturating_sub(retained.len());
        let keep = remaining.min(read);
        retained.extend_from_slice(&buffer[..keep]);
        truncated |= keep < read;
    }
    Ok((retained, truncated))
}

pub(crate) fn inferred_receipt(
    resolved: ResolvedExecutable,
    version: Option<String>,
    pid: Option<u32>,
    cwd: Option<PathBuf>,
) -> HarnessLaunchReceipt {
    let cwd_trust = if cwd.is_some() {
        WorkingDirectoryTrust::ValidatedLocal
    } else {
        WorkingDirectoryTrust::NotApplicable
    };
    HarnessLaunchReceipt {
        harness: resolved.harness,
        executable: resolved.path,
        source: resolved.source,
        version,
        pid,
        cwd,
        cwd_trust,
        auth_state: HarnessAuthState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn executable(path: &Path, contents: &str) {
        use std::os::unix::fs::PermissionsExt;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn configured_absolute_then_path_then_trusted_order_is_stable() {
        let temp = tempfile::tempdir().unwrap();
        let configured = temp.path().join("configured/claude");
        let path_bin = temp.path().join("path/claude");
        let trusted = temp.path().join("home/.local/bin/claude");
        for path in [&configured, &path_bin, &trusted] {
            executable(path, "#!/bin/sh\nexit 0\n");
        }
        let env = LaunchEnvironment::from_pairs([
            (
                OsString::from("PATH"),
                path_bin.parent().unwrap().as_os_str().to_os_string(),
            ),
            (
                OsString::from("HOME"),
                temp.path().join("home").into_os_string(),
            ),
        ]);

        let explicit =
            resolve_harness_executable(HarnessKind::Claude, Some(&configured), &env).unwrap();
        assert_eq!(explicit.source, ExecutableSource::ConfiguredAbsolute);
        assert_eq!(explicit.path, configured.canonicalize().unwrap());

        let ordered = ordered_harness_candidates(HarnessKind::Claude, None, &env).unwrap();
        assert_eq!(ordered[0].source, ExecutableSource::UserPath);
        assert_eq!(ordered[0].path, path_bin.canonicalize().unwrap());
        assert_eq!(ordered[1].source, ExecutableSource::TrustedLocation);
        assert_eq!(ordered[1].path, trusted.canonicalize().unwrap());
    }

    #[test]
    fn relative_configured_path_is_rejected() {
        let env = LaunchEnvironment::from_pairs([]);
        let error =
            resolve_harness_executable(HarnessKind::Codex, Some(Path::new("relative/codex")), &env)
                .unwrap_err();
        assert!(matches!(
            error,
            ResolveExecutableError::RelativeConfiguredPath { .. }
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn capability_probe_is_time_and_output_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let noisy = temp.path().join("opencode");
        executable(
            &noisy,
            "#!/bin/sh\nhead -c 32768 /dev/zero\nhead -c 32768 /dev/zero >&2\n",
        );
        let env = LaunchEnvironment::from_pairs([(
            OsString::from("PATH"),
            OsString::from("/usr/bin:/bin"),
        )]);
        let resolved = ResolvedExecutable {
            harness: HarnessKind::Opencode,
            path: noisy,
            source: ExecutableSource::ConfiguredAbsolute,
        };
        let output = probe_harness(&resolved, [], &env, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(output.stdout.len(), MAX_PROBE_OUTPUT_BYTES);
        assert_eq!(output.stderr.len(), MAX_PROBE_OUTPUT_BYTES);
        assert!(output.output_truncated);

        let hanging = temp.path().join("claude");
        executable(&hanging, "#!/bin/sh\nsleep 60\n");
        let hanging = ResolvedExecutable {
            harness: HarnessKind::Claude,
            path: hanging,
            source: ExecutableSource::ConfiguredAbsolute,
        };
        let started = std::time::Instant::now();
        let error = probe_harness(&hanging, [], &env, Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(matches!(error, HarnessProbeError::Timeout { .. }));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn capability_probe_cleans_descendants_that_hold_output_pipes() {
        let temp = tempfile::tempdir().unwrap();
        let forking = temp.path().join("claude");
        executable(&forking, "#!/bin/sh\n(sleep 30) &\necho ok\n");
        let env = LaunchEnvironment::from_pairs([(
            OsString::from("PATH"),
            OsString::from("/usr/bin:/bin"),
        )]);
        let resolved = ResolvedExecutable {
            harness: HarnessKind::Claude,
            path: forking,
            source: ExecutableSource::ConfiguredAbsolute,
        };

        let started = std::time::Instant::now();
        let output = probe_harness(&resolved, [], &env, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ok");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn cwd_validation_requires_an_existing_absolute_directory() {
        assert!(validate_local_working_directory(Path::new("relative")).is_err());
        let temp = tempfile::tempdir().unwrap();
        assert_eq!(
            validate_local_working_directory(temp.path()).unwrap(),
            temp.path().canonicalize().unwrap()
        );
    }
}
