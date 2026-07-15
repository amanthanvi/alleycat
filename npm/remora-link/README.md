# remora-link

The zero-dependency npm launcher for the Remora Link host bridge.

```sh
npx --yes --prefer-online remora-link@latest
# Reproducible invocation:
npx --yes remora-link@0.1.0 status
```

The launcher selects the exact-version native package for the current
platform and verifies that its package version matches. Commands that install
or respawn the daemon atomically copy the binary into a stable per-user
versioned directory first. Read-only commands such as `status` run directly
without creating a persistent install. The resulting launchd, systemd-user, or
Windows Startup entry never points into a transient npx cache.

Remora Link detects and launches coding-agent harnesses already installed by
the user. It does not install Codex, Claude, OpenCode, Pi, or any other harness.

Supported release targets are macOS arm64/x64, glibc 2.35-or-newer Linux
arm64/x64, and Windows x64. Linux binaries are built and smoke-tested on the
Ubuntu 22.04 baseline; older glibc and musl hosts fail closed in the launcher.

The native packages are internal exact-version dependencies under the
`@remora` scope (`link-darwin-*`, `link-linux-*-gnu`, and
`link-win32-x64-msvc`). They are not intended to be invoked directly.
