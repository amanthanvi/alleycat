//! Process launcher seam.
//!
//! Bridges spawn agent processes (`pi-coding-agent`, `claude`, `opencode`) and,
//! in the case of pi/claude, also spawn shell-tool subprocesses via the
//! `command_exec` codex protocol. Today every spawn site builds a
//! `tokio::process::Command` directly. To let downstream consumers (the daemon,
//! Remora) substitute a remote launcher (e.g. SSH) without touching bridge
//! internals, every spawn is routed through the [`ProcessLauncher`] trait
//! defined here.
//!
//! [`LocalLauncher`] is the default implementation. It wraps
//! `tokio::process::Command` with `kill_on_drop(true)` so a dropped child
//! doesn't outlive the bridge, and suppresses visible console windows for
//! detached Windows daemons.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::Command;

use crate::harness::HarnessLaunchReceipt;

/// Why a process is being launched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessRole {
    /// Long-lived coding-agent process owned by a bridge pool.
    Agent,
    /// Short-lived shell/tool command spawned by `command_exec`.
    ToolCommand,
    /// Short-lived, passive version/capability probe.
    Probe,
}

/// Stdio configuration for one of `stdin` / `stdout` / `stderr`.
///
/// Mirrors the subset of `std::process::Stdio` bridges actually use. `Inherit`
/// is only meaningful for `stderr` — the bridges keep stdin/stdout piped so
/// they can speak JSON-RPC over them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioMode {
    Piped,
    Null,
    Inherit,
}

impl StdioMode {
    fn to_std(self) -> Stdio {
        match self {
            StdioMode::Piped => Stdio::piped(),
            StdioMode::Null => Stdio::null(),
            StdioMode::Inherit => Stdio::inherit(),
        }
    }
}

/// Specification of a process to launch. Bridges populate this and hand it to
/// a [`ProcessLauncher`] without caring whether the resulting child runs
/// locally, on a remote host, or in a sandbox.
#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub role: ProcessRole,
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub cwd: Option<PathBuf>,
    /// Environment variables to set on the child. Unless `env_clear` is true,
    /// these are layered on top of the launcher's default environment; each
    /// entry overrides any inherited value with the same key.
    pub env: Vec<(OsString, OsString)>,
    /// Start the child from exactly `env` instead of inheriting the launcher
    /// process environment first.
    pub env_clear: bool,
    pub stdin: StdioMode,
    pub stdout: StdioMode,
    pub stderr: StdioMode,
}

impl ProcessSpec {
    /// Build a spec with all stdio piped and no extra env.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            env: Vec::new(),
            env_clear: false,
            role: ProcessRole::Agent,
            stdin: StdioMode::Piped,
            stdout: StdioMode::Piped,
            stderr: StdioMode::Piped,
        }
    }
}

/// Type-erased writer over the child's stdin pipe.
pub type ChildStdin = Box<dyn AsyncWrite + Send + Unpin>;
/// Type-erased reader over the child's stdout pipe.
pub type ChildStdout = Box<dyn AsyncRead + Send + Unpin>;
/// Type-erased reader over the child's stderr pipe.
pub type ChildStderr = Box<dyn AsyncRead + Send + Unpin>;

/// Handle to a launched child process.
///
/// Methods that take `&mut self` (e.g. `wait`, `kill`) match `tokio::process::Child`
/// so the local impl is a thin pass-through. The `take_*` methods consume the
/// pipe — calling them twice returns `None` the second time, exactly like
/// `tokio::process::Child`.
pub trait ChildProcess: Send + Sync {
    fn take_stdin(&mut self) -> Option<ChildStdin>;
    fn take_stdout(&mut self) -> Option<ChildStdout>;
    fn take_stderr(&mut self) -> Option<ChildStderr>;
    /// OS process id, when one is meaningful (`None` for remote launchers
    /// that don't expose one).
    fn id(&self) -> Option<u32>;
    /// Redacted launch metadata when the launcher can provide it.
    fn launch_receipt(&self) -> Option<&HarnessLaunchReceipt> {
        None
    }
    /// Non-blocking exit check. Remote launchers may leave the default
    /// unsupported implementation and still participate in forced shutdown.
    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "launcher does not support try_wait",
        ))
    }
    fn wait(&mut self) -> BoxFuture<'_, std::io::Result<ExitStatus>>;
    /// Request termination of the complete owned process tree. Local Unix
    /// children receive SIGTERM through their dedicated process group.
    fn terminate_tree(&mut self) -> BoxFuture<'_, std::io::Result<()>> {
        self.kill()
    }
    /// Force termination of the complete owned process tree.
    fn kill_tree(&mut self) -> BoxFuture<'_, std::io::Result<()>> {
        self.kill()
    }
    fn kill(&mut self) -> BoxFuture<'_, std::io::Result<()>>;
}

/// Launch handle. Implementations are typically `Arc`-wrapped (`Arc<dyn
/// ProcessLauncher>`) and shared across the bridge.
pub trait ProcessLauncher: Send + Sync {
    fn launch(&self, spec: ProcessSpec) -> BoxFuture<'_, std::io::Result<Box<dyn ChildProcess>>>;
}

/// Default launcher: forks a local process via `tokio::process::Command` with
/// `kill_on_drop(true)` so children don't outlive the bridge that owns them.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalLauncher;

impl LocalLauncher {
    pub fn new() -> Self {
        Self
    }
}

impl ProcessLauncher for LocalLauncher {
    fn launch(&self, spec: ProcessSpec) -> BoxFuture<'_, std::io::Result<Box<dyn ChildProcess>>> {
        Box::pin(async move {
            let mut cmd = Command::new(&spec.program);
            cmd.args(&spec.args);
            if let Some(cwd) = &spec.cwd {
                cmd.current_dir(cwd);
            }
            if spec.env_clear {
                cmd.env_clear();
            }
            for (k, v) in &spec.env {
                cmd.env(k, v);
            }
            cmd.stdin(spec.stdin.to_std());
            cmd.stdout(spec.stdout.to_std());
            cmd.stderr(spec.stderr.to_std());
            cmd.kill_on_drop(true);
            #[cfg(unix)]
            configure_unix_process_group(&mut cmd);
            #[cfg(windows)]
            configure_windows_process(&mut cmd);
            #[allow(unused_mut)]
            let mut child = cmd.spawn()?;
            #[cfg(unix)]
            let process_group = child.id();
            #[cfg(windows)]
            let job = match WindowsJob::assign(child.id()) {
                Ok(job) => job,
                Err(error) => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    return Err(error);
                }
            };
            #[cfg(windows)]
            if let Err(error) = resume_windows_process(child.id()) {
                let _ = job.terminate(1);
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(error);
            }
            Ok(Box::new(LocalChild {
                inner: child,
                #[cfg(unix)]
                process_group,
                #[cfg(windows)]
                job: Some(job),
            }) as Box<dyn ChildProcess>)
        })
    }
}

#[cfg(unix)]
fn configure_unix_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.as_std_mut().process_group(0);
}

#[cfg(windows)]
fn configure_windows_process(command: &mut Command) {
    use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};

    // Suspending at creation closes the spawn-to-Job assignment race: even a
    // fast `.cmd` wrapper cannot create descendants before it belongs to the
    // KILL_ON_JOB_CLOSE object. The primary thread is resumed only after the
    // assignment succeeds.
    command.creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED);
}

#[cfg(windows)]
fn resume_windows_process(pid: Option<u32>) -> std::io::Result<()> {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    let pid = pid.ok_or_else(|| std::io::Error::other("spawned child has no process id"))?;
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    let mut entry: THREADENTRY32 = unsafe { zeroed() };
    entry.dwSize = size_of::<THREADENTRY32>() as u32;
    let mut found = false;
    let mut current = unsafe { Thread32First(snapshot, &mut entry) };
    while current != FALSE {
        if entry.th32OwnerProcessID == pid {
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID) };
            if thread.is_null() {
                unsafe { CloseHandle(snapshot) };
                return Err(std::io::Error::last_os_error());
            }
            let resumed = unsafe { ResumeThread(thread) };
            unsafe { CloseHandle(thread) };
            if resumed == u32::MAX {
                unsafe { CloseHandle(snapshot) };
                return Err(std::io::Error::last_os_error());
            }
            found = true;
        }
        current = unsafe { Thread32Next(snapshot, &mut entry) };
    }
    unsafe { CloseHandle(snapshot) };

    if found {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "spawned process primary thread was not found",
        ))
    }
}

struct LocalChild {
    inner: tokio::process::Child,
    /// The child leads a dedicated process group. Retain its original id even
    /// after Tokio reaps the root so descendants cannot escape cleanup.
    #[cfg(unix)]
    process_group: Option<u32>,
    #[cfg(windows)]
    job: Option<WindowsJob>,
}

impl Drop for LocalChild {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(process_group) = self.process_group {
            // Async owners use shutdown_owned_child for a graceful SIGTERM
            // path. This synchronous fallback prevents grandchildren from
            // escaping if a runtime is torn down without that hook running.
            unsafe {
                libc::kill(-(process_group as i32), libc::SIGKILL);
            }
        }
        // On Windows, dropping `job` closes a KILL_ON_JOB_CLOSE job object.
        // Tokio's kill_on_drop handles the root process on other platforms.
    }
}

impl ChildProcess for LocalChild {
    fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.inner.stdin.take().map(|s| Box::new(s) as ChildStdin)
    }

    fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.inner.stdout.take().map(|s| Box::new(s) as ChildStdout)
    }

    fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.inner.stderr.take().map(|s| Box::new(s) as ChildStderr)
    }

    fn id(&self) -> Option<u32> {
        self.inner.id()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.inner.try_wait()
    }

    fn wait(&mut self) -> BoxFuture<'_, std::io::Result<ExitStatus>> {
        Box::pin(async move { self.inner.wait().await })
    }

    fn terminate_tree(&mut self) -> BoxFuture<'_, std::io::Result<()>> {
        #[cfg(unix)]
        {
            let process_group = self.process_group;
            Box::pin(async move { signal_unix_process_group(process_group, libc::SIGTERM) })
        }
        #[cfg(windows)]
        {
            Box::pin(async move {
                if let Some(job) = &self.job {
                    job.terminate(1)
                } else {
                    self.inner.kill().await
                }
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            Box::pin(async move { self.inner.kill().await })
        }
    }

    fn kill_tree(&mut self) -> BoxFuture<'_, std::io::Result<()>> {
        #[cfg(unix)]
        {
            let process_group = self.process_group;
            Box::pin(async move { signal_unix_process_group(process_group, libc::SIGKILL) })
        }
        #[cfg(windows)]
        {
            Box::pin(async move {
                if let Some(job) = &self.job {
                    job.terminate(1)
                } else {
                    self.inner.kill().await
                }
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            Box::pin(async move { self.inner.kill().await })
        }
    }

    fn kill(&mut self) -> BoxFuture<'_, std::io::Result<()>> {
        Box::pin(async move { self.inner.kill().await })
    }
}

#[cfg(unix)]
fn signal_unix_process_group(process_group: Option<u32>, signal: i32) -> std::io::Result<()> {
    let Some(process_group) = process_group else {
        return Ok(());
    };
    // LocalLauncher starts every child as the leader of a fresh process group,
    // so a negative pid targets only the owned harness tree.
    let result = unsafe { libc::kill(-(process_group as i32), signal) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

/// Close protocol input before calling this function. It grants the child a
/// bounded grace window, escalates to a whole-tree terminate request, then to
/// a whole-tree force kill, and always attempts to reap the root process.
pub async fn shutdown_owned_child(
    mut child: Box<dyn ChildProcess>,
    graceful_timeout: Duration,
    terminate_timeout: Duration,
) -> std::io::Result<ExitStatus> {
    if let Ok(result) = tokio::time::timeout(graceful_timeout, child.wait()).await {
        // The root may exit while descendants keep running (and keep inherited
        // pipes open). Always drain the dedicated process group before
        // returning, even after a clean root exit.
        let _ = child.terminate_tree().await;
        let _ = child.kill_tree().await;
        return result;
    }

    let _ = child.terminate_tree().await;
    if let Ok(result) = tokio::time::timeout(terminate_timeout, child.wait()).await {
        let _ = child.kill_tree().await;
        return result;
    }

    let _ = child.kill_tree().await;
    match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "owned child did not exit after forced process-tree termination",
        )),
    }
}

#[cfg(windows)]
struct WindowsJob {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
unsafe impl Send for WindowsJob {}
#[cfg(windows)]
unsafe impl Sync for WindowsJob {}

#[cfg(windows)]
impl WindowsJob {
    fn assign(pid: Option<u32>) -> std::io::Result<Self> {
        use std::mem::{size_of, zeroed};
        use std::ptr::null;
        use windows_sys::Win32::Foundation::{CloseHandle, FALSE};
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        };

        let pid = pid.ok_or_else(|| std::io::Error::other("spawned child has no process id"))?;
        let handle = unsafe { CreateJobObjectW(null(), null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == FALSE {
            unsafe { CloseHandle(handle) };
            return Err(std::io::Error::last_os_error());
        }

        let process = unsafe {
            OpenProcess(
                PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                pid,
            )
        };
        if process.is_null() {
            unsafe { CloseHandle(handle) };
            return Err(std::io::Error::last_os_error());
        }
        let assigned = unsafe { AssignProcessToJobObject(handle, process) };
        unsafe { CloseHandle(process) };
        if assigned == FALSE {
            unsafe { CloseHandle(handle) };
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { handle })
    }

    fn terminate(&self, exit_code: u32) -> std::io::Result<()> {
        use windows_sys::Win32::Foundation::FALSE;
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        if unsafe { TerminateJobObject(self.handle, exit_code) } == FALSE {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsJob {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}
