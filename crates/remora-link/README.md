# Remora Link

Remora Link is the neutral, Remora-owned host wrapper around Remora. It runs
on the user's computer, exposes the installed coding-agent harnesses to paired
Remora clients, and delegates the complete CLI and daemon lifecycle to
`remora::App`.

The wrapper deliberately contains no harness installer or package-manager
fallback. Remora detects configured executables already present on the host
and launches those executables directly. A missing harness stays unavailable
until the user installs it through that harness's own trusted distribution
channel.

## Source build

```sh
cargo build --locked --release -p remora-link --bins
./target/release/remora-link agents list
```

End-user releases are distributed through the zero-dependency `remora-link`
npm launcher. The launcher selects an exact-version platform package. Before a
command can install or respawn the daemon, it copies the Rust binary to a stable
per-user versioned directory and executes it from there. Read-only foreground
commands such as `status` run without creating that persistent install.
Consequently, `npx remora-link install` registers a stable executable path
rather than a transient npm cache path.

See [MAINTENANCE.md](MAINTENANCE.md) for fork policy, upstream sync, and the
relay-provider boundary.
