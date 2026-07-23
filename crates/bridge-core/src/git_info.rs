use std::path::Path;
use std::process::Command;

use remora_codex_proto::GitInfo;

/// Best-effort Git metadata for a thread cwd.
///
/// Codex derives this from the working directory when listing threads. Bridges
/// already know each thread's cwd, so mirror the same surface without persisting
/// it into bridge indexes. Missing git, non-repo paths, detached heads, and
/// repos without an origin simply leave individual fields empty.
pub fn git_info_for_cwd(cwd: impl AsRef<Path>) -> Option<GitInfo> {
    let cwd = cwd.as_ref();
    if cwd.as_os_str().is_empty() || !cwd.is_dir() {
        return None;
    }

    let sha = git_output(cwd, &["rev-parse", "--verify", "HEAD"]);
    let branch = git_output(cwd, &["branch", "--show-current"]);
    let origin_url = git_output(cwd, &["config", "--get", "remote.origin.url"]);

    if sha.is_none() && branch.is_none() && origin_url.is_none() {
        return None;
    }

    Some(GitInfo {
        sha,
        branch,
        origin_url,
    })
}

fn git_output(cwd: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let value = text.lines().next().unwrap_or("").trim();
    if value.is_empty() || value == "HEAD" {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_git(cwd: &Path, args: &[&str]) -> bool {
        Command::new("git")
            .arg("-C")
            .arg(cwd)
            .args(args)
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    #[test]
    fn returns_none_for_non_repo() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(git_info_for_cwd(dir.path()), None);
    }

    #[test]
    fn reads_git_metadata_from_cwd() {
        if !git_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        if !run_git(dir.path(), &["init", "-b", "main"]) {
            assert!(run_git(dir.path(), &["init"]));
        }
        assert!(run_git(
            dir.path(),
            &["config", "user.email", "test@example.com"]
        ));
        assert!(run_git(dir.path(), &["config", "user.name", "Test User"]));
        assert!(run_git(
            dir.path(),
            &["remote", "add", "origin", "https://example.com/repo.git"]
        ));
        std::fs::write(dir.path().join("README.md"), "hello\n").unwrap();
        assert!(run_git(dir.path(), &["add", "README.md"]));
        assert!(run_git(dir.path(), &["commit", "-m", "init"]));

        let info = git_info_for_cwd(dir.path()).expect("expected git metadata");
        assert!(info.sha.as_deref().is_some_and(|sha| sha.len() == 40));
        assert!(
            info.branch
                .as_deref()
                .is_some_and(|branch| !branch.is_empty())
        );
        assert_eq!(
            info.origin_url.as_deref(),
            Some("https://example.com/repo.git")
        );
    }
}
