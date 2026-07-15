use std::collections::BTreeSet;

use clap::{Args, Subcommand};

use crate::cli;
use crate::daemon::control::{
    PairingApprovalResult, PairingApprovalScope, PairingRejectionResult, Request, Response,
};
use crate::pairing_v2::PendingPairingSummary;

#[derive(Args, Debug)]
pub struct PairingArgs {
    #[command(subcommand)]
    pub command: PairingCommand,
}

#[derive(Subcommand, Debug)]
pub enum PairingCommand {
    /// List redacted claims waiting for local host confirmation.
    Pending,
    /// Approve one claim, optionally narrowing runtimes and scopes.
    Approve {
        /// Opaque claim identifier printed by 'pairing pending'.
        #[arg(value_parser = parse_claim_id)]
        claim_id: String,
        /// Grant only this requested runtime. Repeat to retain more than one.
        /// Omitting the option retains every runtime requested by the claim.
        #[arg(
            long = "runtime",
            value_name = "ID",
            value_parser = super::pair::parse_runtime_id
        )]
        runtime_ids: Vec<String>,
        /// Grant only this requested scope. Repeat as needed. Self-revocation
        /// is always retained and is not a selectable scope.
        #[arg(long = "scope", value_name = "SCOPE", value_enum)]
        scopes: Vec<PairingApprovalScope>,
    },
    /// Reject one pending claim. Repeating the command is safe.
    Reject {
        /// Opaque claim identifier printed by 'pairing pending'.
        #[arg(value_parser = parse_claim_id)]
        claim_id: String,
    },
}

pub async fn run(args: PairingArgs) -> anyhow::Result<()> {
    if let PairingCommand::Approve {
        runtime_ids,
        scopes,
        ..
    } = &args.command
    {
        validate_runtime_narrowing(runtime_ids)?;
        validate_scope_narrowing(scopes)?;
    }
    cli::ensure_current_daemon().await?;
    match args.command {
        PairingCommand::Pending => {
            let response = cli::send(Request::PairingsPending).await?;
            print_decoded::<Vec<PendingPairingSummary>>(response)
        }
        PairingCommand::Approve {
            claim_id,
            runtime_ids,
            scopes,
        } => {
            let response = cli::send(Request::PairingApprove {
                claim_id,
                runtime_ids: (!runtime_ids.is_empty()).then_some(runtime_ids),
                scopes: (!scopes.is_empty()).then_some(scopes),
            })
            .await?;
            print_decoded::<PairingApprovalResult>(response)
        }
        PairingCommand::Reject { claim_id } => {
            let response = cli::send(Request::PairingReject { claim_id }).await?;
            print_decoded::<PairingRejectionResult>(response)
        }
    }
}

fn validate_runtime_narrowing(runtime_ids: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(
        runtime_ids.len() <= 16,
        "at most 16 --runtime values are allowed"
    );
    let mut unique = BTreeSet::new();
    anyhow::ensure!(
        runtime_ids.iter().all(|runtime| unique.insert(runtime)),
        "duplicate --runtime values are not allowed"
    );
    Ok(())
}

fn validate_scope_narrowing(scopes: &[PairingApprovalScope]) -> anyhow::Result<()> {
    let mut unique = BTreeSet::new();
    anyhow::ensure!(
        scopes.iter().all(|scope| unique.insert(*scope)),
        "duplicate --scope values are not allowed"
    );
    anyhow::ensure!(
        scopes.is_empty() || scopes.contains(&PairingApprovalScope::Connect),
        "an explicit --scope narrowing must retain --scope connect; self-revoke remains implicit"
    );
    Ok(())
}

fn parse_claim_id(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("claim ID must be 1-128 ASCII letters, digits, hyphens, or underscores".into());
    }
    Ok(value.to_owned())
}

fn print_decoded<T>(response: Response) -> anyhow::Result<()>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let data: T = cli::decode_data(response)?;
    println!("{}", serde_json::to_string(&data)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_runtime_narrowing_is_rejected() {
        let runtimes = vec!["codex".to_string(), "codex".to_string()];
        let error = validate_runtime_narrowing(&runtimes).unwrap_err();
        assert!(error.to_string().contains("duplicate --runtime"));
    }

    #[test]
    fn explicit_scope_narrowing_must_retain_connect() {
        let error = validate_scope_narrowing(&[PairingApprovalScope::Inspect]).unwrap_err();
        assert!(error.to_string().contains("--scope connect"));
        assert!(validate_scope_narrowing(&[PairingApprovalScope::Connect]).is_ok());
    }
}
