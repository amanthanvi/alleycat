use clap::Args;
use qrcodegen::{QrCode, QrCodeEcc};

use crate::cli;
use crate::daemon::control::{PairingResultV2, Request};
use crate::protocol::PairPayload;

#[derive(Args, Debug)]
pub struct PairArgs {
    /// Render an ASCII QR code for the pair payload.
    #[arg(long)]
    pub qr: bool,
    /// Temporary migration escape hatch through 2026-10-15: emit the legacy
    /// alleycat/1 bearer. It cannot create or upgrade a v2 device grant.
    #[arg(long)]
    pub legacy: bool,
}

pub async fn run(args: PairArgs) -> anyhow::Result<()> {
    // ensure_current_daemon() handles every state: no daemon, stale
    // daemon, current daemon. After this call, a v<this binary> daemon
    // is up on the IPC socket — and crucially, that daemon is the only
    // path that has the iroh endpoint and can populate the `relay` field
    // in the pair payload. We deliberately don't fall back to a
    // daemon-less "build payload from disk" mode, because that mode can't
    // emit a relay URL and the resulting QR is undialable on networks
    // where pkarr/DNS publishing is broken.
    cli::ensure_current_daemon().await?;

    if args.legacy {
        let resp = cli::send(Request::PairLegacy).await?;
        let payload: PairPayload = cli::decode_data(resp)?;
        let json = serde_json::to_string(&payload)?;
        println!("{json}");
        if args.qr {
            println!();
            print_qr(&json)?;
        }
    } else {
        let resp = cli::send(Request::Pair).await?;
        let result: PairingResultV2 = cli::decode_data(resp)?;
        // JSON is stable for integrations; the URI-like envelope is the
        // canonical full-entropy copy/paste and QR representation.
        println!("{}", serde_json::to_string(&result.invitation)?);
        println!("{}", result.code);
        if args.qr {
            println!();
            print_qr(&result.code)?;
        }
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
