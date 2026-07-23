use clap::{Args, Subcommand};

use crate::cli;
use crate::daemon::control::{DeviceRevokeResult, Request};
use crate::pairing_v2::DeviceSummary;

#[derive(Args, Debug)]
pub struct DevicesArgs {
    #[command(subcommand)]
    command: DevicesCommand,
}

#[derive(Subcommand, Debug)]
enum DevicesCommand {
    /// Print redacted v2 device grants as stable JSON.
    List,
    /// Revoke exactly one device grant and close its live connections.
    Revoke { device_id: String },
}

pub async fn run(args: DevicesArgs) -> anyhow::Result<()> {
    cli::ensure_current_daemon().await?;
    match args.command {
        DevicesCommand::List => {
            let response = cli::send(Request::DevicesList).await?;
            let devices: Vec<DeviceSummary> = cli::decode_data(response)?;
            println!("{}", serde_json::to_string(&devices)?);
        }
        DevicesCommand::Revoke { device_id } => {
            let response = cli::send(Request::DeviceRevoke { device_id }).await?;
            let result: DeviceRevokeResult = cli::decode_data(response)?;
            println!("{}", serde_json::to_string(&result.device)?);
        }
    }
    Ok(())
}
