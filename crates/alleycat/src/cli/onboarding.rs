//! Default flow when the binary is invoked with no subcommand. Designed
//! for `npx kittylitter` first-run UX:
//!
//! 1. Install the OS-level autostart entry if it's missing (so future
//!    user logins bring the daemon up on their own). Errors here are
//!    warnings only — we still bring the daemon up ourselves below.
//! 2. Bring a daemon of *this* binary's version online via
//!    `cli::ensure_current_daemon`, which handles every state the user
//!    might be in: no daemon, stale daemon, supervisor wedged, plist
//!    pointing at a moved binary, etc.
//! 3. Print the pair payload with a QR code so the user can pair their
//!    phone immediately.
//!
//! Goal: the entire sequence is one command (`npx kittylitter`) with no
//! follow-up `serve`/`stop`/`install` rituals required.

use crate::cli;
use crate::service;

pub async fn run() -> anyhow::Result<()> {
    let name = crate::binary_name();

    if !service::is_installed().unwrap_or(false) {
        println!("First run — installing {name} as a user-level autostart...");
        if let Err(error) = service::install() {
            eprintln!("warning: installing autostart failed: {error:#}; continuing without it");
        }
    }

    // ensure_current_daemon does whatever it takes to leave a
    // v<this binary> daemon listening on the IPC socket: spawns one if
    // none is up, restarts a stale one, falls back to a setsid-detached
    // spawn if the supervisor is wedged. Same path `pair`/`rotate` use,
    // so onboarding stays honest about runtime state.
    cli::ensure_current_daemon().await?;

    cli::pair::run(cli::pair::PairArgs {
        qr: true,
        legacy: false,
    })
    .await
}
