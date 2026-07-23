use clap::Args;
use qrcodegen::{QrCode, QrCodeEcc};
use zeroize::Zeroizing;

use crate::cli;
use crate::daemon::control::{PairingResultV2, Request};

#[derive(Args, Debug)]
pub struct PairArgs {
    /// Render an ASCII QR code for the pair payload.
    #[arg(long)]
    pub qr: bool,
    /// Runtime ID this invitation may access. Repeat to authorize more than
    /// one runtime. V2 requires an explicit, bounded allowlist.
    #[arg(
        long = "runtime",
        value_name = "ID",
        required = true,
        value_parser = parse_runtime_id
    )]
    pub runtime_ids: Vec<String>,
    /// Permit the paired device to restart an approved runtime. Runtime
    /// inspection/listing, connection, and self-revocation are otherwise the
    /// complete default grant.
    #[arg(long, conflicts_with = "unattended")]
    pub allow_restart: bool,
    /// Skip the normal bilateral SAS/device/scope confirmation. This weaker
    /// mode is restricted to one runtime, cannot restart it, and expires in
    /// at most 60 seconds.
    #[arg(
        long,
        conflicts_with = "allow_restart",
        requires = "i_understand_first_claimer_wins"
    )]
    pub unattended: bool,
    /// Explicitly acknowledge that anyone who obtains an unattended invite
    /// before it expires can win its one allowed claim.
    #[arg(long, requires = "unattended")]
    pub i_understand_first_claimer_wins: bool,
    /// Override the invitation lifetime in seconds. Interactive invitations
    /// are capped at 300 seconds; unattended invitations at 60 seconds.
    #[arg(
        long,
        value_name = "SECONDS",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub ttl_secs: Option<u64>,
}

pub async fn run(args: PairArgs) -> anyhow::Result<()> {
    validate_v2_options(&args)?;
    // ensure_current_daemon() handles every state: no daemon, stale
    // daemon, current daemon. After this call, a v<this binary> daemon
    // is up on the IPC socket — and crucially, that daemon is the only
    // path that has the iroh endpoint and can populate the `relay` field
    // in the pair payload. We deliberately don't fall back to a
    // daemon-less "build payload from disk" mode, because that mode can't
    // emit a relay URL and the resulting QR is undialable on networks
    // where pkarr/DNS publishing is broken.
    cli::ensure_current_daemon().await?;

    let ttl_secs = args.ttl_secs.or(args.unattended.then_some(60));
    if args.unattended {
        eprintln!(
            "WARNING: unattended pairing skips bilateral host confirmation. This invite is limited to one runtime, cannot restart it, and expires within 60 seconds."
        );
    }
    let resp = cli::send(Request::Pair {
        runtime_ids: args.runtime_ids.clone(),
        allow_restart: args.allow_restart,
        unattended: args.unattended,
        ttl_secs,
    })
    .await?;
    let result: PairingResultV2 = cli::decode_data(resp)?;
    // JSON is stable for integrations; the URI-like envelope is the
    // canonical full-entropy copy/paste and QR representation.
    let invitation_json = Zeroizing::new(serde_json::to_string(&result.invitation)?);
    println!("{}", invitation_json.as_str());
    println!("{}", result.code);
    if args.qr {
        println!();
        print_qr(&result.code)?;
    }
    if args.unattended {
        eprintln!(
            "Access ceiling: inspect/list and connect to {}; self-revoke is always included.",
            args.runtime_ids.join(", ")
        );
    } else {
        let restart = if args.allow_restart { ", restart" } else { "" };
        eprintln!(
            "Host confirmation is required after claim for runtime(s) {} and scope(s) inspect/list, connect{restart}; self-revoke is always included.",
            args.runtime_ids.join(", ")
        );
        eprintln!(
            "Review pending claims with `{} pairing pending`.",
            crate::binary_name()
        );
    }
    Ok(())
}

pub(crate) fn parse_runtime_id(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(
            "runtime ID must be 1-64 ASCII letters, digits, hyphens, or underscores".into(),
        );
    }
    Ok(value.to_owned())
}

fn validate_v2_options(args: &PairArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        !args.runtime_ids.is_empty(),
        "at least one --runtime is required"
    );
    anyhow::ensure!(
        args.runtime_ids.len() <= 16,
        "at most 16 --runtime values are allowed"
    );
    let mut unique = std::collections::BTreeSet::new();
    anyhow::ensure!(
        args.runtime_ids
            .iter()
            .all(|runtime| unique.insert(runtime)),
        "duplicate --runtime values are not allowed"
    );
    if args.unattended {
        anyhow::ensure!(
            args.i_understand_first_claimer_wins,
            "--unattended requires --i-understand-first-claimer-wins"
        );
        anyhow::ensure!(
            args.runtime_ids.len() == 1,
            "--unattended requires exactly one --runtime"
        );
        anyhow::ensure!(
            !args.allow_restart,
            "--unattended cannot be combined with --allow-restart"
        );
        anyhow::ensure!(
            args.ttl_secs.is_none_or(|ttl| ttl <= 60),
            "--unattended --ttl-secs cannot exceed 60"
        );
    } else {
        anyhow::ensure!(
            args.ttl_secs
                .is_none_or(|ttl| ttl <= crate::pairing_v2::DEFAULT_INVITATION_TTL.as_secs()),
            "--ttl-secs cannot exceed 300 for interactive pairing"
        );
    }
    Ok(())
}

fn print_qr(data: &str) -> anyhow::Result<()> {
    // Low ECC over Medium: ~7% capacity loss vs ~15%, often shaves one
    // version off the matrix. The QR is rendered on a clean digital screen
    // for a phone camera at close range — there's no dirt/glare to recover
    // from, so the higher levels are wasted bits.
    let code = QrCode::encode_text(data, QrCodeEcc::Low)
        .map_err(|err| anyhow::anyhow!("encoding QR: {err:?}"))?;
    let size = code.size();
    let border = 2_i32;
    let lo = -border;
    let hi = size + border;

    // Render two QR rows per terminal row using upper/lower half-block
    // glyphs (U+2580 ▀, U+2584 ▄, U+2588 █). Halves the vertical size of
    // the rendered code; combined with one-cell-per-module width, the QR
    // ends up roughly square in normal terminal aspect ratios.
    let module = |x: i32, y: i32| -> bool {
        if y < 0 || y >= size {
            false
        } else {
            code.get_module(x, y)
        }
    };
    let mut y = lo;
    while y < hi {
        let mut line = String::with_capacity((hi - lo) as usize);
        for x in lo..hi {
            let top = module(x, y);
            let bot = module(x, y + 1);
            line.push(match (top, bot) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        println!("{line}");
        y += 2;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_args(runtime_ids: Vec<&str>) -> PairArgs {
        PairArgs {
            qr: false,
            runtime_ids: runtime_ids.into_iter().map(str::to_owned).collect(),
            allow_restart: false,
            unattended: false,
            i_understand_first_claimer_wins: false,
            ttl_secs: None,
        }
    }

    #[test]
    fn duplicate_runtime_ceiling_is_rejected_before_ipc() {
        let args = v2_args(vec!["codex", "codex"]);
        let error = validate_v2_options(&args).unwrap_err();
        assert!(error.to_string().contains("duplicate --runtime"));
    }

    #[test]
    fn unattended_ceiling_is_one_runtime_and_sixty_seconds() {
        let mut args = v2_args(vec!["codex", "pi"]);
        args.unattended = true;
        args.i_understand_first_claimer_wins = true;
        assert!(
            validate_v2_options(&args)
                .unwrap_err()
                .to_string()
                .contains("exactly one")
        );

        args.runtime_ids = vec!["codex".to_string()];
        args.ttl_secs = Some(61);
        assert!(
            validate_v2_options(&args)
                .unwrap_err()
                .to_string()
                .contains("cannot exceed 60")
        );
    }

    #[test]
    fn interactive_invitation_cannot_outlive_default_window() {
        let mut args = v2_args(vec!["codex"]);
        args.ttl_secs = Some(301);
        let error = validate_v2_options(&args).unwrap_err();
        assert!(error.to_string().contains("cannot exceed 300"));
    }
}
