//! Remora Link pairing protocol v2.
//!
//! This ALPN deliberately has no bearer-token upgrade path. Invitations are
//! short-lived, one-time capability envelopes. Grants are bound to a device
//! P-256 key and authenticated Iroh endpoint, and every operation requires a
//! fresh proof of possession plus a least-privilege scope check.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use iroh::endpoint::{Connection, VarInt};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, OwnedRwLockReadGuard, RwLock};
use tracing::{error, warn};
use zeroize::{Zeroize, Zeroizing};

use remora_bridge_core::command_center::HostCommandCenterStatusV1;

use crate::protocol::{AgentInfo, SessionInfo};

pub const PROTOCOL_VERSION_V2: u32 = 2;
pub const REMORA_LINK_ALPN: &[u8] = b"remora-link/2";
pub const PAIRING_CODE_PREFIX: &str = "remora-link:v2:";
pub const DEFAULT_INVITATION_TTL: Duration = Duration::from_secs(5 * 60);
pub const MAX_UNATTENDED_INVITATION_TTL: Duration = Duration::from_secs(60);
pub const PROOF_TRANSCRIPT_DOMAIN: &[u8] = b"remora-link/2/proof/v2";
pub const OPERATION_PAYLOAD_DOMAIN: &[u8] = b"remora-link/2/payload/v2";
pub const SAS_DOMAIN: &[u8] = b"remora-link/2/sas/v2";

const STORE_VERSION: u32 = 3;
const INVITATION_ID_BYTES: usize = 16;
const INVITATION_SECRET_BYTES: usize = 32;
const DEVICE_ID_BYTES: usize = 16;
const CLAIM_ID_BYTES: usize = 16;
const NONCE_BYTES: usize = 32;
const CHALLENGE_ID_BYTES: usize = 16;
const MAX_OPEN_INVITATIONS: usize = 16;
const MAX_RUNTIME_IDS: usize = 16;
const MAX_RUNTIME_ID_BYTES: usize = 64;
const MAX_DEVICE_NAME_BYTES: usize = 80;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const MAX_ENDPOINT_ID_BYTES: usize = 256;
const MAX_PAIRING_CODE_SEGMENT_BYTES: usize = 4096;
const TOMBSTONE_RETENTION_SECS: i64 = 90 * 24 * 60 * 60;
const CHALLENGE_TTL: Duration = Duration::from_secs(30);
const MAX_RECENT_CLIENT_NONCES: usize = 256;
const MAX_RECENT_NONCE_SUBJECTS: usize = 1024;
const MAX_RESTART_COMMANDS_PER_DEVICE: usize = 256;
const MAX_ACTIVE_CONNECTIONS_PER_CREDENTIAL: usize = 8;
const SECRET_HASH_DOMAIN: &[u8] = b"remora-link/pairing-v2/invitation-secret\0";
const ENROLLMENT_TRANSCRIPT_DOMAIN: &[u8] = b"remora-link/2/enrollment/v2";
const ENROLLMENT_REQUEST_FINGERPRINT_DOMAIN: &[u8] = b"remora-link/2/enrollment-request/v2";
const POLICY_DIGEST_DOMAIN: &[u8] = b"remora-link/2/policy/v2";
const PROSPECTIVE_CREDENTIAL_DOMAIN: &[u8] = b"remora-link/2/prospective-credential/v2";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DeviceScopeV2 {
    InspectRuntimes,
    ConnectRuntime,
    RestartRuntime,
    SelfRevoke,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationModeV2 {
    Interactive,
    Unattended,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResumeV2 {
    pub last_seq: u64,
}

#[derive(Debug, Clone)]
pub struct InvitationOptions {
    pub max_runtime_ids: Vec<String>,
    pub max_scopes: Vec<DeviceScopeV2>,
    pub confirmation_mode: ConfirmationModeV2,
    pub ttl: Duration,
}

impl InvitationOptions {
    pub fn interactive(max_runtime_ids: Vec<String>, allow_restart: bool) -> Self {
        let mut max_scopes = vec![
            DeviceScopeV2::InspectRuntimes,
            DeviceScopeV2::ConnectRuntime,
            DeviceScopeV2::SelfRevoke,
        ];
        if allow_restart {
            max_scopes.push(DeviceScopeV2::RestartRuntime);
        }
        Self {
            max_runtime_ids,
            max_scopes,
            confirmation_mode: ConfirmationModeV2::Interactive,
            ttl: DEFAULT_INVITATION_TTL,
        }
    }

    pub fn unattended(runtime_id: String) -> Self {
        Self {
            max_runtime_ids: vec![runtime_id],
            max_scopes: vec![
                DeviceScopeV2::InspectRuntimes,
                DeviceScopeV2::ConnectRuntime,
                DeviceScopeV2::SelfRevoke,
            ],
            confirmation_mode: ConfirmationModeV2::Unattended,
            ttl: MAX_UNATTENDED_INVITATION_TTL,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairingInvitation {
    pub v: u32,
    pub node_id: String,
    pub invitation_id: String,
    pub secret: String,
    pub expires_at: i64,
    pub max_runtime_ids: Vec<String>,
    pub max_scopes: Vec<DeviceScopeV2>,
    pub confirmation_mode: ConfirmationModeV2,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
}

impl PairingInvitation {
    pub fn to_pairing_code(&self) -> anyhow::Result<String> {
        let json = pairing_invitation_json(self)?;
        let encoded = URL_SAFE_NO_PAD.encode(json.as_slice());
        Ok(format!("{PAIRING_CODE_PREFIX}{encoded}"))
    }

    pub fn from_pairing_code(code: &str) -> anyhow::Result<Self> {
        let encoded = code
            .trim()
            .strip_prefix(PAIRING_CODE_PREFIX)
            .ok_or_else(|| anyhow!("unsupported pairing code"))?;
        if encoded.len() > MAX_PAIRING_CODE_SEGMENT_BYTES {
            return Err(anyhow!("pairing code is too large"));
        }
        let json = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .context("decoding pairing code")?,
        );
        let invitation: Self =
            serde_json::from_slice(&json).context("parsing pairing invitation")?;
        if invitation.v != PROTOCOL_VERSION_V2
            || !valid_opaque_id(&invitation.invitation_id)
            || URL_SAFE_NO_PAD
                .decode(&invitation.secret)
                .ok()
                .is_none_or(|v| v.len() != INVITATION_SECRET_BYTES)
            || invitation.node_id.parse::<iroh::PublicKey>().is_err()
            || invitation
                .host_name
                .as_ref()
                .is_some_and(|name| !valid_label(name, 255))
            || invitation
                .relay
                .as_ref()
                .is_some_and(|relay| relay.parse::<iroh::RelayUrl>().is_err())
            || validate_policy_shape(
                &invitation.max_runtime_ids,
                &invitation.max_scopes,
                invitation.confirmation_mode,
            )
            .is_err()
        {
            return Err(anyhow!("invalid pairing invitation"));
        }
        Ok(invitation)
    }

    pub fn zeroize_secret(&mut self) {
        self.secret.zeroize();
    }
}

impl Drop for PairingInvitation {
    fn drop(&mut self) {
        self.zeroize_secret();
    }
}

impl fmt::Debug for PairingInvitation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingInvitation")
            .field("v", &self.v)
            .field("node_id", &self.node_id)
            .field("invitation_id", &self.invitation_id)
            .field("secret", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("max_runtime_ids", &self.max_runtime_ids)
            .field("max_scopes", &self.max_scopes)
            .field("confirmation_mode", &self.confirmation_mode)
            .field("host_name", &self.host_name)
            .field("relay", &self.relay)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestV2 {
    InspectInvitation {
        v: u32,
        invitation_id: String,
        secret: String,
        device_public_key: String,
        client_nonce: String,
    },
    Enroll {
        v: u32,
        invitation_id: String,
        secret: String,
        #[serde(default)]
        device_name: String,
        device_public_key: String,
        selected_runtime_ids: Vec<String>,
        requested_scopes: Vec<DeviceScopeV2>,
        idempotency_key: String,
        client_nonce: String,
    },
    ListAgents {
        v: u32,
        credential_id: String,
        client_nonce: String,
    },
    CommandCenterStatus {
        v: u32,
        credential_id: String,
        client_nonce: String,
    },
    RestartAgent {
        v: u32,
        credential_id: String,
        client_nonce: String,
        agent: String,
        idempotency_key: String,
        command_sequence: u64,
    },
    Connect {
        v: u32,
        credential_id: String,
        client_nonce: String,
        agent: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resume: Option<ResumeV2>,
    },
    RevokeSelf {
        v: u32,
        credential_id: String,
        client_nonce: String,
        idempotency_key: String,
    },
    RollbackEnrollment {
        v: u32,
        credential_id: String,
        enrollment_idempotency_key: String,
        client_nonce: String,
        idempotency_key: String,
    },
}

impl RequestV2 {
    pub fn version(&self) -> u32 {
        match self {
            Self::InspectInvitation { v, .. }
            | Self::Enroll { v, .. }
            | Self::ListAgents { v, .. }
            | Self::CommandCenterStatus { v, .. }
            | Self::RestartAgent { v, .. }
            | Self::Connect { v, .. }
            | Self::RevokeSelf { v, .. }
            | Self::RollbackEnrollment { v, .. } => *v,
        }
    }

    pub fn operation(&self) -> &'static str {
        match self {
            Self::InspectInvitation { .. } => "inspect_invitation",
            Self::Enroll { .. } => "enroll",
            Self::ListAgents { .. } => "list_agents",
            Self::CommandCenterStatus { .. } => "command_center_status",
            Self::RestartAgent { .. } => "restart_agent",
            Self::Connect { .. } => "connect",
            Self::RevokeSelf { .. } => "revoke_self",
            Self::RollbackEnrollment { .. } => "rollback_enrollment",
        }
    }

    pub fn client_nonce(&self) -> &str {
        match self {
            Self::InspectInvitation { client_nonce, .. }
            | Self::Enroll { client_nonce, .. }
            | Self::ListAgents { client_nonce, .. }
            | Self::CommandCenterStatus { client_nonce, .. }
            | Self::RestartAgent { client_nonce, .. }
            | Self::Connect { client_nonce, .. }
            | Self::RevokeSelf { client_nonce, .. }
            | Self::RollbackEnrollment { client_nonce, .. } => client_nonce,
        }
    }

    pub fn credential_id(&self) -> Option<&str> {
        match self {
            Self::InspectInvitation { .. } | Self::Enroll { .. } => None,
            Self::ListAgents { credential_id, .. }
            | Self::CommandCenterStatus { credential_id, .. }
            | Self::RestartAgent { credential_id, .. }
            | Self::Connect { credential_id, .. }
            | Self::RevokeSelf { credential_id, .. }
            | Self::RollbackEnrollment { credential_id, .. } => Some(credential_id),
        }
    }

    pub fn operation_payload_hash(&self) -> [u8; 32] {
        match self {
            Self::InspectInvitation {
                invitation_id,
                secret,
                device_public_key,
                ..
            } => hash_operation_payload(&[invitation_id, secret, device_public_key]),
            Self::Enroll {
                invitation_id,
                secret,
                device_name,
                device_public_key,
                selected_runtime_ids,
                requested_scopes,
                idempotency_key,
                ..
            } => hash_operation_payload(&[
                invitation_id,
                secret,
                device_name,
                device_public_key,
                &canonical_runtime_ids(selected_runtime_ids),
                &canonical_scopes(requested_scopes),
                idempotency_key,
            ]),
            Self::ListAgents { .. } => hash_operation_payload(&[]),
            Self::CommandCenterStatus { .. } => hash_operation_payload(&[]),
            Self::RestartAgent {
                agent,
                idempotency_key,
                command_sequence,
                ..
            } => hash_operation_payload(&[agent, idempotency_key, &command_sequence.to_string()]),
            Self::Connect { agent, resume, .. } => {
                let cursor = resume
                    .as_ref()
                    .map(|v| v.last_seq.to_string())
                    .unwrap_or_default();
                hash_operation_payload(&[agent, &cursor])
            }
            Self::RevokeSelf {
                idempotency_key, ..
            } => hash_operation_payload(&[idempotency_key]),
            Self::RollbackEnrollment {
                enrollment_idempotency_key,
                idempotency_key,
                ..
            } => hash_operation_payload(&[enrollment_idempotency_key, idempotency_key]),
        }
    }

    /// Clear invitation bearer material as soon as inspect/enroll processing
    /// finishes. The host calls this before retaining or dropping a decoded
    /// request so the allocator does not keep a live copy of the raw secret.
    pub fn zeroize_invitation_secret(&mut self) {
        match self {
            Self::InspectInvitation { secret, .. } | Self::Enroll { secret, .. } => {
                secret.zeroize();
            }
            _ => {}
        }
    }
}

impl Drop for RequestV2 {
    fn drop(&mut self) {
        self.zeroize_invitation_secret();
    }
}

impl fmt::Debug for RequestV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(self.operation())
            .field("v", &self.version())
            .field("credential_id", &self.credential_id())
            .field("client_nonce", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProofChallengeV2 {
    pub challenge_id: String,
    pub credential_id: String,
    pub auth_epoch: u64,
    pub server_nonce: String,
    pub expires_at: i64,
}

impl ProofChallengeV2 {
    pub fn issue(credential_id: String, auth_epoch: u64) -> Self {
        Self::issue_at(credential_id, auth_epoch, unix_now())
    }

    fn issue_at(credential_id: String, auth_epoch: u64, now: i64) -> Self {
        Self {
            challenge_id: random_urlsafe(CHALLENGE_ID_BYTES),
            credential_id,
            auth_epoch,
            server_nonce: random_urlsafe(NONCE_BYTES),
            expires_at: now.saturating_add(CHALLENGE_TTL.as_secs() as i64),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofV2 {
    pub v: u32,
    pub challenge_id: String,
    pub signature: String,
}

impl fmt::Debug for ProofV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProofV2")
            .field("v", &self.v)
            .field("challenge_id", &self.challenge_id)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCodeV2 {
    PairingUnavailable,
    AuthorizationRequired,
    InvalidRequest,
    AgentUnavailable,
    OutcomeUnknown,
    Internal,
}

impl ErrorCodeV2 {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::PairingUnavailable => "pairing unavailable",
            Self::AuthorizationRequired => "device authorization required",
            Self::InvalidRequest => "invalid request",
            Self::AgentUnavailable => "agent unavailable",
            Self::OutcomeUnknown => "operation outcome unknown",
            Self::Internal => "request failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrolledDevice {
    pub device_id: String,
    pub display_name: String,
    pub endpoint_fingerprint: String,
    pub device_key_fingerprint: String,
    pub selected_runtime_ids: Vec<String>,
    pub granted_scopes: Vec<DeviceScopeV2>,
    pub auth_epoch: u64,
    pub created_at: i64,
    pub enrollment_confirmation: EnrollmentConfirmationV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentConfirmationV2 {
    pub transcript_hash: String,
    pub sas: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvitationInspectionV2 {
    pub invitation_id: String,
    pub expires_at: i64,
    pub max_runtime_ids: Vec<String>,
    pub max_scopes: Vec<DeviceScopeV2>,
    pub confirmation_mode: ConfirmationModeV2,
    pub runtime_offers: Vec<RuntimeOfferV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeOfferV2 {
    pub runtime_id: String,
    pub display_name: String,
    pub available: bool,
    pub recommended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingEnrollmentV2 {
    pub claim_id: String,
    pub credential_id: String,
    pub display_name: String,
    pub selected_runtime_ids: Vec<String>,
    pub requested_scopes: Vec<DeviceScopeV2>,
    pub enrollment_confirmation: EnrollmentConfirmationV2,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EnrollmentOutcomeV2 {
    Pending { pending: PendingEnrollmentV2 },
    Enrolled { enrolled: EnrolledDevice },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingPairingSummary {
    pub claim_id: String,
    pub credential_id: String,
    pub display_name: String,
    pub endpoint_fingerprint: String,
    pub device_key_fingerprint: String,
    pub selected_runtime_ids: Vec<String>,
    pub requested_scopes: Vec<DeviceScopeV2>,
    pub sas: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationContextV2 {
    pub credential_id: String,
    pub auth_epoch: u64,
    pub selected_runtime_ids: Vec<String>,
    pub granted_scopes: Vec<DeviceScopeV2>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RestartStatusV2 {
    Succeeded,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestartResultV2 {
    pub agent: String,
    pub idempotency_key: String,
    pub command_sequence: u64,
    pub status: RestartStatusV2,
}

/// A linearization fence for one newly prepared restart command.
///
/// The host must retain this value through runtime dispatch and pass it to
/// [`PairingManager::mark_restart_succeeded`]. Dropping it releases the
/// credential's read fence and allows revocation to commit.
#[must_use = "retain the restart dispatch fence until runtime dispatch finishes"]
pub struct RestartDispatchV2 {
    command_id: String,
    credential_id: String,
    agent: String,
    idempotency_key: String,
    command_sequence: u64,
    _permit: OwnedRwLockReadGuard<()>,
}

impl RestartDispatchV2 {
    pub fn command_id(&self) -> &str {
        &self.command_id
    }

    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    pub fn agent(&self) -> &str {
        &self.agent
    }

    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub fn command_sequence(&self) -> u64 {
        self.command_sequence
    }
}

impl fmt::Debug for RestartDispatchV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RestartDispatchV2")
            .field("command_id", &self.command_id)
            .field("credential_id", &self.credential_id)
            .field("agent", &self.agent)
            .field("idempotency_key", &"[REDACTED]")
            .field("command_sequence", &self.command_sequence)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum RestartPreparationV2 {
    Execute(RestartDispatchV2),
    OutcomeUnknown(RestartResultV2),
    Succeeded(RestartResultV2),
}

/// Short-lived linearization fence for starting a runtime attachment.
///
/// Retain this only through bridge/process attachment setup, then drop it
/// before entering the long-lived stream.
#[must_use = "retain the connect-start fence until runtime attachment finishes"]
pub struct ConnectStartPermitV2 {
    credential_id: String,
    _permit: OwnedRwLockReadGuard<()>,
}

impl ConnectStartPermitV2 {
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }
}

impl fmt::Debug for ConnectStartPermitV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectStartPermitV2")
            .field("credential_id", &self.credential_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationReceiptV2 {
    pub credential_id: String,
    pub auth_epoch: u64,
    pub revoked_at: i64,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", content = "receipt", rename_all = "snake_case")]
pub enum RevocationMutationV2 {
    Durable(RevocationReceiptV2),
    OutcomeUnknown(RevocationReceiptV2),
}

impl RevocationMutationV2 {
    pub fn receipt(&self) -> &RevocationReceiptV2 {
        match self {
            Self::Durable(receipt) | Self::OutcomeUnknown(receipt) => receipt,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseV2 {
    pub v: u32,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<ProofChallengeV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled: Option<EnrolledDevice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspection: Option<InvitationInspectionV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<PendingEnrollmentV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<RevocationReceiptV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<RestartResultV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<AgentInfo>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_center_status: Option<HostCommandCenterStatusV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<ErrorCodeV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ResponseV2 {
    fn success() -> Self {
        Self {
            v: PROTOCOL_VERSION_V2,
            ok: true,
            challenge: None,
            enrolled: None,
            inspection: None,
            pending: None,
            revocation: None,
            restart: None,
            agents: None,
            command_center_status: None,
            session: None,
            error_code: None,
            error: None,
        }
    }
    pub fn ok() -> Self {
        Self::success()
    }
    pub fn challenge(value: ProofChallengeV2) -> Self {
        Self {
            challenge: Some(value),
            ..Self::success()
        }
    }
    pub fn enrolled(value: EnrolledDevice) -> Self {
        Self {
            enrolled: Some(value),
            ..Self::success()
        }
    }
    pub fn inspection(value: InvitationInspectionV2) -> Self {
        Self {
            inspection: Some(value),
            ..Self::success()
        }
    }
    pub fn pending(value: PendingEnrollmentV2) -> Self {
        Self {
            pending: Some(value),
            ..Self::success()
        }
    }
    pub fn revocation(value: RevocationReceiptV2) -> Self {
        Self {
            revocation: Some(value),
            ..Self::success()
        }
    }
    pub fn revocation_outcome_unknown(value: RevocationReceiptV2) -> Self {
        Self {
            v: PROTOCOL_VERSION_V2,
            ok: false,
            challenge: None,
            enrolled: None,
            inspection: None,
            pending: None,
            revocation: Some(value),
            restart: None,
            agents: None,
            command_center_status: None,
            session: None,
            error_code: Some(ErrorCodeV2::OutcomeUnknown),
            error: Some(ErrorCodeV2::OutcomeUnknown.message().to_string()),
        }
    }
    pub fn restart(value: RestartResultV2) -> Self {
        match value.status {
            RestartStatusV2::Succeeded => Self {
                restart: Some(value),
                ..Self::success()
            },
            RestartStatusV2::OutcomeUnknown => Self {
                v: PROTOCOL_VERSION_V2,
                ok: false,
                challenge: None,
                enrolled: None,
                inspection: None,
                pending: None,
                revocation: None,
                restart: Some(value),
                agents: None,
                command_center_status: None,
                session: None,
                error_code: Some(ErrorCodeV2::OutcomeUnknown),
                error: Some(ErrorCodeV2::OutcomeUnknown.message().to_string()),
            },
        }
    }
    pub fn agents(value: Vec<AgentInfo>) -> Self {
        Self {
            agents: Some(value),
            ..Self::success()
        }
    }
    pub fn command_center_status(value: HostCommandCenterStatusV1) -> Self {
        Self {
            command_center_status: Some(value),
            ..Self::success()
        }
    }
    pub fn session(value: SessionInfo) -> Self {
        Self {
            session: Some(value),
            ..Self::success()
        }
    }
    pub fn error(code: ErrorCodeV2) -> Self {
        Self {
            v: PROTOCOL_VERSION_V2,
            ok: false,
            challenge: None,
            enrolled: None,
            inspection: None,
            pending: None,
            revocation: None,
            restart: None,
            agents: None,
            command_center_status: None,
            session: None,
            error_code: Some(code),
            error: Some(code.message().to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceSummary {
    pub device_id: String,
    pub display_name: String,
    pub endpoint_fingerprint: String,
    pub device_key_fingerprint: String,
    pub selected_runtime_ids: Vec<String>,
    pub granted_scopes: Vec<DeviceScopeV2>,
    pub auth_epoch: u64,
    pub state: GrantStateV2,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GrantStateV2 {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RedeemError {
    #[error("pairing unavailable")]
    Unavailable,
    #[error("pairing unavailable")]
    DurabilityUnknown,
    #[error("agent unavailable")]
    AgentUnavailable,
}

#[derive(Debug)]
enum CommitDurability {
    Durable,
    CommittedUnknown(anyhow::Error),
}

#[derive(Default)]
struct RecentNonceCache {
    subjects: HashMap<String, VecDeque<String>>,
    lru: VecDeque<String>,
}

impl RecentNonceCache {
    fn record(&mut self, subject: &str, nonce: &str) -> bool {
        if self.subjects.contains_key(subject) {
            self.lru.retain(|value| value != subject);
        } else {
            while self.subjects.len() >= MAX_RECENT_NONCE_SUBJECTS {
                let Some(evicted) = self.lru.pop_front() else {
                    break;
                };
                self.subjects.remove(&evicted);
            }
            self.subjects.insert(subject.to_string(), VecDeque::new());
        }
        self.lru.push_back(subject.to_string());
        let recent = self
            .subjects
            .get_mut(subject)
            .expect("nonce subject was inserted");
        if recent.iter().any(|value| value == nonce) {
            return false;
        }
        recent.push_back(nonce.to_string());
        while recent.len() > MAX_RECENT_CLIENT_NONCES {
            recent.pop_front();
        }
        true
    }
}

#[derive(Clone)]
pub struct PairingManager {
    path: PathBuf,
    state: Arc<Mutex<PersistedState>>,
    active: Arc<Mutex<HashMap<String, Vec<Connection>>>>,
    recent_client_nonces: Arc<Mutex<RecentNonceCache>>,
    operation_gates: Arc<Mutex<HashMap<String, Arc<RwLock<()>>>>>,
    durability_unknown: Arc<AtomicBool>,
}

struct ProofExchange<'a> {
    challenge: &'a ProofChallengeV2,
    proof: &'a ProofV2,
    host_endpoint_id: &'a str,
    client_endpoint_id: &'a str,
}

impl PairingManager {
    pub async fn load_default() -> anyhow::Result<Self> {
        Self::load(crate::paths::pairing_v2_file()?).await
    }

    pub async fn load(path: PathBuf) -> anyhow::Result<Self> {
        let mut state = match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed: PersistedState = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing {}", path.display()))?;
                if parsed.version != STORE_VERSION {
                    return Err(anyhow!(
                        "unsupported pairing store version {} in {}; Remora Link v2 grants must be re-paired",
                        parsed.version,
                        path.display()
                    ));
                }
                parsed
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => PersistedState::default(),
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        };
        let before = serde_json::to_vec(&state).context("serializing loaded pairing store")?;
        let now = unix_now();
        sanitize_loaded_invitations(&mut state, now);
        sweep_expired(&mut state, now);
        if before != serde_json::to_vec(&state).context("serializing sanitized pairing store")? {
            let bytes = serde_json::to_vec_pretty(&state).context("serializing pairing store")?;
            match atomic_write(&path, &bytes).await? {
                CommitDurability::Durable => {}
                CommitDurability::CommittedUnknown(error) => {
                    return Err(error.context(
                        "sanitized pairing store was committed but directory durability is unknown",
                    ));
                }
            }
        }
        Ok(Self {
            path,
            state: Arc::new(Mutex::new(state)),
            active: Arc::new(Mutex::new(HashMap::new())),
            recent_client_nonces: Arc::new(Mutex::new(RecentNonceCache::default())),
            operation_gates: Arc::new(Mutex::new(HashMap::new())),
            durability_unknown: Arc::new(AtomicBool::new(false)),
        })
    }

    pub async fn create_invitation(
        &self,
        node_id: String,
        host_name: Option<String>,
        relay: Option<String>,
        options: InvitationOptions,
    ) -> anyhow::Result<PairingInvitation> {
        self.create_invitation_at(node_id, host_name, relay, options, unix_now())
            .await
    }

    async fn create_invitation_at(
        &self,
        node_id: String,
        host_name: Option<String>,
        relay: Option<String>,
        mut options: InvitationOptions,
        now: i64,
    ) -> anyhow::Result<PairingInvitation> {
        canonicalize_runtime_ids(&mut options.max_runtime_ids)?;
        canonicalize_scopes(&mut options.max_scopes)?;
        validate_policy(
            &options.max_runtime_ids,
            &options.max_scopes,
            options.confirmation_mode,
            options.ttl,
        )?;
        if node_id.len() > MAX_ENDPOINT_ID_BYTES || node_id.parse::<iroh::PublicKey>().is_err() {
            return Err(anyhow!("invalid host endpoint id"));
        }
        if host_name.as_ref().is_some_and(|v| !valid_label(v, 255)) {
            return Err(anyhow!("invalid host name"));
        }
        if relay
            .as_ref()
            .is_some_and(|v| v.parse::<iroh::RelayUrl>().is_err())
        {
            return Err(anyhow!("invalid relay url"));
        }

        let mut guard = self.state.lock().await;
        self.confirm_current_state_durability(&guard).await?;
        let mut next = guard.clone();
        sweep_expired(&mut next, now);
        if next
            .invitations
            .values()
            .filter(|v| v.terminal_at.is_none())
            .count()
            >= MAX_OPEN_INVITATIONS
        {
            return Err(anyhow!("too many open pairing invitations"));
        }

        let invitation_id = unique_invitation_id(&next);
        let secret = random_urlsafe(INVITATION_SECRET_BYTES);
        let expires_at = now.saturating_add(options.ttl.as_secs() as i64);
        let invitation = PairingInvitation {
            v: PROTOCOL_VERSION_V2,
            node_id,
            invitation_id: invitation_id.clone(),
            secret: secret.clone(),
            expires_at,
            max_runtime_ids: options.max_runtime_ids.clone(),
            max_scopes: options.max_scopes.clone(),
            confirmation_mode: options.confirmation_mode,
            host_name,
            relay,
        };
        // Validate the complete serialized envelope before the one-time
        // secret is committed. This prevents a long but syntactically valid
        // relay URL from creating an invitation no decoder can accept.
        pairing_invitation_json(&invitation)?;
        next.invitations.insert(
            invitation_id.clone(),
            InvitationRecord {
                invitation_id: invitation_id.clone(),
                secret_hash: hex::encode(invitation_secret_hash(&secret)),
                created_at: now,
                expires_at,
                max_runtime_ids: options.max_runtime_ids.clone(),
                max_scopes: options.max_scopes.clone(),
                confirmation_mode: options.confirmation_mode,
                claim: None,
                terminal_at: None,
            },
        );
        match self.commit_state(&mut guard, next).await? {
            CommitDurability::Durable => Ok(invitation),
            CommitDurability::CommittedUnknown(error) => Err(error
                .context("pairing invitation was committed but directory durability is unknown")),
        }
    }

    pub async fn issue_challenge(
        &self,
        request: &RequestV2,
        authenticated_client_endpoint_id: &str,
    ) -> Result<ProofChallengeV2, RedeemError> {
        validate_request(request)?;
        let state = self.state.lock().await;
        let (credential_id, auth_epoch) = match request {
            RequestV2::InspectInvitation { invitation_id, .. } => (invitation_id.clone(), 0),
            RequestV2::Enroll {
                invitation_id,
                device_public_key,
                idempotency_key,
                ..
            } => {
                if authenticated_client_endpoint_id.len() > MAX_ENDPOINT_ID_BYTES {
                    return Err(RedeemError::Unavailable);
                }
                (
                    prospective_credential_id(
                        invitation_id,
                        authenticated_client_endpoint_id,
                        device_public_key,
                        idempotency_key,
                    )?,
                    0,
                )
            }
            _ => {
                let id = request.credential_id().ok_or(RedeemError::Unavailable)?;
                let epoch = state
                    .devices
                    .get(id)
                    .map(|v| v.auth_epoch)
                    .or_else(|| find_claim_by_credential(&state, id).map(|(_, v)| v.auth_epoch))
                    .unwrap_or(0);
                (id.to_string(), epoch)
            }
        };
        Ok(ProofChallengeV2::issue(credential_id, auth_epoch))
    }

    pub async fn inspect(
        &self,
        request: &RequestV2,
        challenge: &ProofChallengeV2,
        proof: &ProofV2,
        host_endpoint_id: &str,
        authenticated_client_endpoint_id: &str,
    ) -> Result<InvitationInspectionV2, RedeemError> {
        self.inspect_at(
            request,
            challenge,
            proof,
            host_endpoint_id,
            authenticated_client_endpoint_id,
            unix_now(),
        )
        .await
    }

    async fn inspect_at(
        &self,
        request: &RequestV2,
        challenge: &ProofChallengeV2,
        proof: &ProofV2,
        host_endpoint_id: &str,
        authenticated_client_endpoint_id: &str,
        now: i64,
    ) -> Result<InvitationInspectionV2, RedeemError> {
        validate_request(request)?;
        validate_challenge_proof(challenge, proof, now)?;
        let RequestV2::InspectInvitation {
            invitation_id,
            secret,
            device_public_key,
            ..
        } = request
        else {
            return Err(RedeemError::Unavailable);
        };
        if challenge.credential_id != *invitation_id
            || challenge.auth_epoch != 0
            || authenticated_client_endpoint_id.len() > MAX_ENDPOINT_ID_BYTES
        {
            return Err(RedeemError::Unavailable);
        }
        verify_request_signature(
            request,
            challenge,
            proof,
            host_endpoint_id,
            authenticated_client_endpoint_id,
            device_public_key,
        )?;
        let result = {
            let state = self.state.lock().await;
            let invitation = state
                .invitations
                .get(invitation_id)
                .filter(|v| {
                    v.expires_at > now
                        && v.terminal_at.is_none()
                        && secret_hash_matches(&v.secret_hash, secret)
                })
                .ok_or(RedeemError::Unavailable)?;
            InvitationInspectionV2 {
                invitation_id: invitation.invitation_id.clone(),
                expires_at: invitation.expires_at,
                max_runtime_ids: invitation.max_runtime_ids.clone(),
                max_scopes: invitation.max_scopes.clone(),
                confirmation_mode: invitation.confirmation_mode,
                runtime_offers: Vec::new(),
            }
        };
        self.record_fresh_client_nonce(
            &format!("inspect:{invitation_id}:{authenticated_client_endpoint_id}"),
            request.client_nonce(),
        )
        .await?;
        Ok(result)
    }

    pub async fn enroll(
        &self,
        request: &RequestV2,
        challenge: &ProofChallengeV2,
        proof: &ProofV2,
        host_endpoint_id: &str,
        authenticated_client_endpoint_id: &str,
    ) -> Result<EnrollmentOutcomeV2, RedeemError> {
        self.enroll_at(
            request,
            challenge,
            proof,
            host_endpoint_id,
            authenticated_client_endpoint_id,
            unix_now(),
        )
        .await
    }

    async fn enroll_at(
        &self,
        request: &RequestV2,
        challenge: &ProofChallengeV2,
        proof: &ProofV2,
        host_endpoint_id: &str,
        authenticated_client_endpoint_id: &str,
        now: i64,
    ) -> Result<EnrollmentOutcomeV2, RedeemError> {
        validate_request(request)?;
        validate_challenge_proof(challenge, proof, now)?;
        let RequestV2::Enroll {
            invitation_id,
            secret,
            device_name,
            device_public_key,
            selected_runtime_ids,
            requested_scopes,
            idempotency_key,
            ..
        } = request
        else {
            return Err(RedeemError::Unavailable);
        };
        if authenticated_client_endpoint_id.len() > MAX_ENDPOINT_ID_BYTES
            || challenge.auth_epoch != 0
        {
            return Err(RedeemError::Unavailable);
        }
        verify_request_signature(
            request,
            challenge,
            proof,
            host_endpoint_id,
            authenticated_client_endpoint_id,
            device_public_key,
        )?;
        let request_fingerprint =
            enrollment_fingerprint(request, host_endpoint_id, authenticated_client_endpoint_id)?;
        self.record_fresh_client_nonce(&challenge.credential_id, request.client_nonce())
            .await?;

        let mut guard = self.state.lock().await;
        self.confirm_current_state_durability(&guard)
            .await
            .map_err(|_| RedeemError::DurabilityUnknown)?;
        let mut next = guard.clone();
        sweep_expired(&mut next, now);
        let invitation = next
            .invitations
            .get(invitation_id)
            .filter(|v| {
                secret_hash_matches(&v.secret_hash, secret)
                    && (v.claim.is_some() || (v.expires_at > now && v.terminal_at.is_none()))
            })
            .cloned()
            .ok_or(RedeemError::Unavailable)?;

        if let Some(claim) = invitation.claim.clone() {
            if claim.idempotency_key != *idempotency_key
                || claim.request_fingerprint != hex::encode(request_fingerprint)
                || claim.endpoint_id != authenticated_client_endpoint_id
            {
                return Err(RedeemError::Unavailable);
            }
            let outcome = claim_outcome(&next, &claim)?;
            return Ok(outcome);
        }
        if next
            .devices
            .values()
            .any(|v| v.endpoint_id == authenticated_client_endpoint_id && v.revoked_at.is_none())
            || next.devices.contains_key(&challenge.credential_id)
        {
            return Err(RedeemError::Unavailable);
        }
        ensure_subset(selected_runtime_ids, &invitation.max_runtime_ids)?;
        ensure_scope_subset(requested_scopes, &invitation.max_scopes)?;
        validate_grant(selected_runtime_ids, requested_scopes)?;
        if invitation.confirmation_mode == ConfirmationModeV2::Unattended
            && (selected_runtime_ids != &invitation.max_runtime_ids
                || requested_scopes.as_slice()
                    != [
                        DeviceScopeV2::InspectRuntimes,
                        DeviceScopeV2::ConnectRuntime,
                        DeviceScopeV2::SelfRevoke,
                    ])
        {
            return Err(RedeemError::Unavailable);
        }

        let display_name = normalize_device_name(device_name);
        let claim_id = unique_claim_id(&next);
        let transcript_hash = enrollment_transcript_hash(EnrollmentTranscriptInput {
            host_endpoint_id,
            client_endpoint_id: authenticated_client_endpoint_id,
            invitation_id,
            device_public_key,
            idempotency_key,
            selected_runtime_ids,
            requested_scopes,
            server_nonce: &challenge.server_nonce,
            client_nonce: request.client_nonce(),
            confirmation_mode: invitation.confirmation_mode,
            max_runtime_ids: &invitation.max_runtime_ids,
            max_scopes: &invitation.max_scopes,
        })
        .map_err(|_| RedeemError::Unavailable)?;
        let claim = EnrollmentClaimRecord {
            claim_id,
            credential_id: challenge.credential_id.clone(),
            idempotency_key: idempotency_key.clone(),
            request_fingerprint: hex::encode(request_fingerprint),
            endpoint_id: authenticated_client_endpoint_id.to_string(),
            device_public_key: device_public_key.clone(),
            display_name,
            selected_runtime_ids: selected_runtime_ids.clone(),
            requested_scopes: requested_scopes.clone(),
            sas: derive_sas(secret, &transcript_hash),
            transcript_hash: URL_SAFE_NO_PAD.encode(transcript_hash),
            created_at: now,
            expires_at: invitation.expires_at,
            auth_epoch: 0,
            status: ClaimStatus::Pending,
        };
        let mode = invitation.confirmation_mode;
        next.invitations
            .get_mut(invitation_id)
            .expect("validated invitation exists")
            .claim = Some(claim.clone());
        let outcome = if mode == ConfirmationModeV2::Unattended {
            let device = DeviceRecord::from_claim(&claim, now);
            let enrolled = device.enrolled();
            next.devices.insert(device.device_id.clone(), device);
            next.invitations
                .get_mut(invitation_id)
                .and_then(|v| v.claim.as_mut())
                .unwrap()
                .status = ClaimStatus::Approved;
            next.invitations.get_mut(invitation_id).unwrap().terminal_at = Some(now);
            EnrollmentOutcomeV2::Enrolled { enrolled }
        } else {
            EnrollmentOutcomeV2::Pending {
                pending: claim.pending(),
            }
        };
        match self.commit_state(&mut guard, next).await {
            Ok(CommitDurability::Durable) => {}
            Ok(CommitDurability::CommittedUnknown(error)) => {
                error!("pairing claim committed with unknown directory durability: {error:#}");
                return Err(RedeemError::DurabilityUnknown);
            }
            Err(error) => {
                error!("persisting pairing claim failed before commit: {error:#}");
                return Err(RedeemError::Unavailable);
            }
        }
        Ok(outcome)
    }

    pub async fn list_pending(&self) -> Vec<PendingPairingSummary> {
        let now = unix_now();
        let mut guard = self.state.lock().await;
        if let Err(error) = self.confirm_current_state_durability(&guard).await {
            error!("pairing-store durability retry failed before expiry sweep: {error:#}");
            let mut pending: Vec<_> = guard
                .invitations
                .values()
                .filter_map(|invitation| {
                    let claim = invitation.claim.as_ref()?;
                    (claim.status == ClaimStatus::Pending && claim.expires_at > now)
                        .then(|| claim.summary())
                })
                .collect();
            pending.sort_by(|a, b| {
                a.created_at
                    .cmp(&b.created_at)
                    .then_with(|| a.claim_id.cmp(&b.claim_id))
            });
            return pending;
        }
        let mut next = guard.clone();
        sweep_expired(&mut next, now);
        if serde_json::to_vec(&next).ok() != serde_json::to_vec(&*guard).ok() {
            match self.commit_state(&mut guard, next).await {
                Ok(CommitDurability::Durable) => {}
                Ok(CommitDurability::CommittedUnknown(error)) => {
                    error!(
                        "expired pairing claims committed with unknown directory durability: {error:#}"
                    );
                }
                Err(error) => {
                    error!("persisting expired pairing claims failed before commit: {error:#}");
                }
            }
        }
        let mut pending: Vec<_> = guard
            .invitations
            .values()
            .filter_map(|v| {
                let claim = v.claim.as_ref()?;
                (claim.status == ClaimStatus::Pending && claim.expires_at > now)
                    .then(|| claim.summary())
            })
            .collect();
        pending.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.claim_id.cmp(&b.claim_id))
        });
        pending
    }

    pub async fn pairing_claim_summary(&self, claim_id: &str) -> Option<PendingPairingSummary> {
        let state = self.state.lock().await;
        state.invitations.values().find_map(|invitation| {
            invitation
                .claim
                .as_ref()
                .filter(|claim| {
                    claim.claim_id == claim_id
                        && matches!(claim.status, ClaimStatus::Pending | ClaimStatus::Approved)
                })
                .map(EnrollmentClaimRecord::summary)
        })
    }

    pub async fn approve_pending(
        &self,
        claim_id: &str,
        selected_runtime_ids: &[String],
        granted_scopes: &[DeviceScopeV2],
    ) -> anyhow::Result<Option<EnrolledDevice>> {
        let now = unix_now();
        let mut runtimes = selected_runtime_ids.to_vec();
        let mut scopes = granted_scopes.to_vec();
        canonicalize_runtime_ids(&mut runtimes)?;
        canonicalize_scopes(&mut scopes)?;
        validate_grant(&runtimes, &scopes).map_err(|_| anyhow!("invalid grant narrowing"))?;

        let mut guard = self.state.lock().await;
        self.confirm_current_state_durability(&guard).await?;
        let mut next = guard.clone();
        sweep_expired(&mut next, now);
        let Some(invitation_id) = find_invitation_id_by_claim(&next, claim_id) else {
            return Ok(None);
        };
        let invitation = next
            .invitations
            .get(&invitation_id)
            .expect("claim invitation exists");
        let claim = invitation.claim.as_ref().expect("claim exists");
        if claim.status == ClaimStatus::Approved {
            let device = next.devices.get(&claim.credential_id);
            if device
                .is_some_and(|v| v.selected_runtime_ids == runtimes && v.granted_scopes == scopes)
            {
                return Ok(device.map(DeviceRecord::enrolled));
            }
            return Err(anyhow!("approval replay does not match committed grant"));
        }
        if claim.status != ClaimStatus::Pending || claim.expires_at <= now {
            return Ok(None);
        }
        ensure_subset(&runtimes, &claim.selected_runtime_ids)
            .map_err(|_| anyhow!("approved runtimes must only narrow the request"))?;
        ensure_scope_subset(&scopes, &claim.requested_scopes)
            .map_err(|_| anyhow!("approved scopes must only narrow the request"))?;
        let mut approved = claim.clone();
        approved.selected_runtime_ids = runtimes;
        approved.requested_scopes = scopes;
        approved.status = ClaimStatus::Approved;
        let device = DeviceRecord::from_claim(&approved, now);
        let enrolled = device.enrolled();
        next.devices.insert(device.device_id.clone(), device);
        let invitation = next
            .invitations
            .get_mut(&invitation_id)
            .expect("invitation exists");
        invitation.claim = Some(approved);
        invitation.terminal_at = Some(now);
        match self.commit_state(&mut guard, next).await? {
            CommitDurability::Durable => Ok(Some(enrolled)),
            CommitDurability::CommittedUnknown(error) => {
                Err(error
                    .context("pairing approval was committed but directory durability is unknown"))
            }
        }
    }

    pub async fn reject_pending(&self, claim_id: &str) -> anyhow::Result<bool> {
        let now = unix_now();
        let mut guard = self.state.lock().await;
        self.confirm_current_state_durability(&guard).await?;
        let mut next = guard.clone();
        sweep_expired(&mut next, now);
        let Some(invitation_id) = find_invitation_id_by_claim(&next, claim_id) else {
            return Ok(false);
        };
        let invitation = next
            .invitations
            .get_mut(&invitation_id)
            .expect("invitation exists");
        let claim = invitation.claim.as_mut().expect("claim exists");
        if claim.status != ClaimStatus::Pending {
            return Ok(claim.status == ClaimStatus::Rejected);
        }
        claim.status = ClaimStatus::Rejected;
        invitation.terminal_at = Some(now);
        match self.commit_state(&mut guard, next).await? {
            CommitDurability::Durable => Ok(true),
            CommitDurability::CommittedUnknown(error) => Err(error
                .context("pairing rejection was committed but directory durability is unknown")),
        }
    }

    pub async fn authorize_operation(
        &self,
        request: &RequestV2,
        challenge: &ProofChallengeV2,
        proof: &ProofV2,
        host_endpoint_id: &str,
        authenticated_client_endpoint_id: &str,
    ) -> Result<AuthorizationContextV2, RedeemError> {
        self.authorize_operation_at(
            request,
            challenge,
            proof,
            host_endpoint_id,
            authenticated_client_endpoint_id,
            unix_now(),
        )
        .await
    }

    async fn authorize_operation_at(
        &self,
        request: &RequestV2,
        challenge: &ProofChallengeV2,
        proof: &ProofV2,
        host_endpoint_id: &str,
        authenticated_client_endpoint_id: &str,
        now: i64,
    ) -> Result<AuthorizationContextV2, RedeemError> {
        validate_request(request)?;
        validate_challenge_proof(challenge, proof, now)?;
        let credential_id = request.credential_id().ok_or(RedeemError::Unavailable)?;
        if credential_id != challenge.credential_id {
            return Err(RedeemError::Unavailable);
        }
        let device = {
            let state = self.state.lock().await;
            if self.confirm_current_state_durability(&state).await.is_err()
                && !matches!(request, RequestV2::RestartAgent { .. })
            {
                return Err(RedeemError::DurabilityUnknown);
            }
            state
                .devices
                .get(credential_id)
                .filter(|v| {
                    v.revoked_at.is_none()
                        && v.endpoint_id == authenticated_client_endpoint_id
                        && v.auth_epoch == challenge.auth_epoch
                })
                .cloned()
                .ok_or(RedeemError::Unavailable)?
        };
        verify_request_signature(
            request,
            challenge,
            proof,
            host_endpoint_id,
            authenticated_client_endpoint_id,
            &device.device_public_key,
        )?;
        enforce_operation_grant(request, &device)?;
        self.record_fresh_client_nonce(credential_id, request.client_nonce())
            .await?;
        Ok(device.authorization())
    }

    /// Durably prepare a restart command while fencing credential revocation.
    ///
    /// `Execute` is returned exactly once, after the `Prepared` journal record
    /// is synced. Replaying a prepared record reports `OutcomeUnknown` and
    /// never dispatches again; replaying a succeeded record reports the same
    /// logical success result.
    pub async fn prepare_restart(
        &self,
        request: &RequestV2,
        authorization: &AuthorizationContextV2,
        authenticated_client_endpoint_id: &str,
        runtime_available: bool,
    ) -> Result<RestartPreparationV2, RedeemError> {
        validate_request(request)?;
        let RequestV2::RestartAgent {
            credential_id,
            agent,
            idempotency_key,
            command_sequence,
            ..
        } = request
        else {
            return Err(RedeemError::Unavailable);
        };
        if authorization.credential_id != *credential_id {
            return Err(RedeemError::Unavailable);
        }

        // The owned read permit is intentionally returned on the execute
        // path. Host-side and self revocation take the matching write permit
        // before touching durable state, so dispatch and revoke have a single
        // observable order.
        let permit = self
            .credential_operation_gate(credential_id)
            .await
            .read_owned()
            .await;
        let mut guard = self.state.lock().await;
        let state_is_durable = match self.confirm_current_state_durability(&guard).await {
            Ok(()) => true,
            Err(error) => {
                error!("pairing-store durability retry failed before restart: {error:#}");
                false
            }
        };
        let device = guard
            .devices
            .get(credential_id)
            .filter(|device| {
                authorization_matches_device(
                    authorization,
                    authenticated_client_endpoint_id,
                    device,
                )
            })
            .ok_or(RedeemError::Unavailable)?;
        enforce_operation_grant(request, device)?;

        let journal_key = restart_journal_key(credential_id, *command_sequence);
        let request_fingerprint = hex::encode(request.operation_payload_hash());
        let high_watermark = guard
            .restart_high_watermarks
            .get(credential_id)
            .copied()
            .unwrap_or(0);
        if *command_sequence <= high_watermark {
            if let Some(existing) = guard.restart_commands.get(&journal_key) {
                if existing.request_fingerprint != request_fingerprint
                    || existing.agent != *agent
                    || existing.idempotency_key != *idempotency_key
                    || existing.command_sequence != *command_sequence
                    || existing.auth_epoch != authorization.auth_epoch
                {
                    return Err(RedeemError::Unavailable);
                }
                let result = existing.result();
                if !state_is_durable {
                    return Ok(RestartPreparationV2::OutcomeUnknown(RestartResultV2 {
                        status: RestartStatusV2::OutcomeUnknown,
                        ..result
                    }));
                }
                return Ok(match existing.status {
                    RestartCommandStatus::Prepared => RestartPreparationV2::OutcomeUnknown(result),
                    RestartCommandStatus::Succeeded => RestartPreparationV2::Succeeded(result),
                });
            }
            return Ok(RestartPreparationV2::OutcomeUnknown(RestartResultV2 {
                agent: agent.clone(),
                idempotency_key: idempotency_key.clone(),
                command_sequence: *command_sequence,
                status: RestartStatusV2::OutcomeUnknown,
            }));
        }
        if !state_is_durable {
            return Err(RedeemError::DurabilityUnknown);
        }
        if high_watermark.checked_add(1) != Some(*command_sequence) {
            return Err(RedeemError::Unavailable);
        }
        if !runtime_available {
            return Err(RedeemError::AgentUnavailable);
        }
        if guard.restart_commands.values().any(|record| {
            record.credential_id == *credential_id
                && record.idempotency_key == *idempotency_key
                && record.command_sequence != *command_sequence
        }) {
            return Err(RedeemError::Unavailable);
        }

        let mut next = guard.clone();
        let command_id = unique_restart_command_id(&next);
        next.restart_high_watermarks
            .insert(credential_id.clone(), *command_sequence);
        next.restart_commands.insert(
            journal_key.clone(),
            RestartCommandRecord {
                command_id: command_id.clone(),
                credential_id: credential_id.clone(),
                idempotency_key: idempotency_key.clone(),
                command_sequence: *command_sequence,
                request_fingerprint,
                agent: agent.clone(),
                auth_epoch: authorization.auth_epoch,
                status: RestartCommandStatus::Prepared,
                created_at: unix_now(),
                succeeded_at: None,
            },
        );
        let mut credential_records: Vec<_> = next
            .restart_commands
            .iter()
            .filter(|(_, record)| record.credential_id == *credential_id)
            .map(|(key, record)| (record.command_sequence, key.clone()))
            .collect();
        credential_records.sort_by_key(|(sequence, _)| *sequence);
        let prune_count = credential_records
            .len()
            .saturating_sub(MAX_RESTART_COMMANDS_PER_DEVICE);
        for (_, key) in credential_records.into_iter().take(prune_count) {
            next.restart_commands.remove(&key);
        }
        let unknown_result = next.restart_commands[&journal_key].result();
        match self.commit_state(&mut guard, next).await {
            Ok(CommitDurability::Durable) => Ok(RestartPreparationV2::Execute(RestartDispatchV2 {
                command_id,
                credential_id: credential_id.clone(),
                agent: agent.clone(),
                idempotency_key: idempotency_key.clone(),
                command_sequence: *command_sequence,
                _permit: permit,
            })),
            Ok(CommitDurability::CommittedUnknown(error)) => {
                error!("prepared restart committed with unknown directory durability: {error:#}");
                Ok(RestartPreparationV2::OutcomeUnknown(unknown_result))
            }
            Err(error) => {
                error!("persisting prepared restart command failed before commit: {error:#}");
                Err(RedeemError::Unavailable)
            }
        }
    }

    pub async fn prepare_connect_start(
        &self,
        authorization: &AuthorizationContextV2,
        authenticated_client_endpoint_id: &str,
    ) -> Result<ConnectStartPermitV2, RedeemError> {
        let permit = self
            .credential_operation_gate(&authorization.credential_id)
            .await
            .read_owned()
            .await;
        let state = self.state.lock().await;
        self.confirm_current_state_durability(&state)
            .await
            .map_err(|_| RedeemError::DurabilityUnknown)?;
        let device = state
            .devices
            .get(&authorization.credential_id)
            .ok_or(RedeemError::Unavailable)?;
        if !authorization_matches_device(authorization, authenticated_client_endpoint_id, device) {
            return Err(RedeemError::Unavailable);
        }
        Ok(ConnectStartPermitV2 {
            credential_id: authorization.credential_id.clone(),
            _permit: permit,
        })
    }

    /// Mark a dispatched restart successful while its revocation fence is
    /// still held. A persistence failure deliberately leaves `Prepared`, so a
    /// retry reports ambiguity instead of executing twice.
    pub async fn mark_restart_succeeded(
        &self,
        dispatch: &RestartDispatchV2,
    ) -> anyhow::Result<RestartResultV2> {
        let journal_key = restart_journal_key(&dispatch.credential_id, dispatch.command_sequence);
        let mut guard = self.state.lock().await;
        self.confirm_current_state_durability(&guard).await?;
        let current = guard
            .restart_commands
            .get(&journal_key)
            .filter(|record| {
                record.command_id == dispatch.command_id
                    && record.credential_id == dispatch.credential_id
                    && record.agent == dispatch.agent
                    && record.idempotency_key == dispatch.idempotency_key
                    && record.command_sequence == dispatch.command_sequence
            })
            .ok_or_else(|| anyhow!("prepared restart command is unavailable"))?;
        if current.status == RestartCommandStatus::Succeeded {
            return Ok(current.result());
        }
        let mut next = guard.clone();
        let record = next
            .restart_commands
            .get_mut(&journal_key)
            .expect("validated restart command exists");
        record.status = RestartCommandStatus::Succeeded;
        record.succeeded_at = Some(unix_now());
        let result = next.restart_commands[&journal_key].result();
        match self.commit_state(&mut guard, next).await? {
            CommitDurability::Durable => Ok(result),
            CommitDurability::CommittedUnknown(error) => {
                error!("restart success committed with unknown directory durability: {error:#}");
                Ok(RestartResultV2 {
                    status: RestartStatusV2::OutcomeUnknown,
                    ..result
                })
            }
        }
    }

    pub async fn self_revoke(
        &self,
        request: &RequestV2,
        challenge: &ProofChallengeV2,
        proof: &ProofV2,
        host_endpoint_id: &str,
        authenticated_client_endpoint_id: &str,
    ) -> Result<RevocationMutationV2, RedeemError> {
        self.revoke_mutation(
            request,
            ProofExchange {
                challenge,
                proof,
                host_endpoint_id,
                client_endpoint_id: authenticated_client_endpoint_id,
            },
            unix_now(),
            false,
        )
        .await
    }

    pub async fn rollback_enrollment(
        &self,
        request: &RequestV2,
        challenge: &ProofChallengeV2,
        proof: &ProofV2,
        host_endpoint_id: &str,
        authenticated_client_endpoint_id: &str,
    ) -> Result<RevocationMutationV2, RedeemError> {
        self.revoke_mutation(
            request,
            ProofExchange {
                challenge,
                proof,
                host_endpoint_id,
                client_endpoint_id: authenticated_client_endpoint_id,
            },
            unix_now(),
            true,
        )
        .await
    }

    async fn revoke_mutation(
        &self,
        request: &RequestV2,
        exchange: ProofExchange<'_>,
        now: i64,
        rollback: bool,
    ) -> Result<RevocationMutationV2, RedeemError> {
        let ProofExchange {
            challenge,
            proof,
            host_endpoint_id,
            client_endpoint_id: authenticated_client_endpoint_id,
        } = exchange;
        validate_request(request)?;
        validate_challenge_proof(challenge, proof, now)?;
        let (credential_id, idempotency_key, enrollment_key) = match request {
            RequestV2::RevokeSelf {
                credential_id,
                idempotency_key,
                ..
            } if !rollback => (credential_id.as_str(), idempotency_key.as_str(), None),
            RequestV2::RollbackEnrollment {
                credential_id,
                enrollment_idempotency_key,
                idempotency_key,
                ..
            } if rollback => (
                credential_id.as_str(),
                idempotency_key.as_str(),
                Some(enrollment_idempotency_key.as_str()),
            ),
            _ => return Err(RedeemError::Unavailable),
        };
        if challenge.credential_id != credential_id {
            return Err(RedeemError::Unavailable);
        }
        let (public_key, expected_endpoint, current_epoch, can_revoke, enrollment_matches) = {
            let state = self.state.lock().await;
            if let Err(error) = self.confirm_current_state_durability(&state).await {
                error!("pairing-store durability retry failed before revocation proof: {error:#}");
            }
            if let Some(device) = state.devices.get(credential_id) {
                let matches = enrollment_key.is_none_or(|key| {
                    find_claim_by_credential(&state, credential_id)
                        .is_some_and(|(_, claim)| claim.idempotency_key == key)
                });
                (
                    device.device_public_key.clone(),
                    device.endpoint_id.clone(),
                    device.auth_epoch,
                    device.granted_scopes.contains(&DeviceScopeV2::SelfRevoke),
                    matches,
                )
            } else if rollback {
                let (_, claim) = find_claim_by_credential(&state, credential_id)
                    .ok_or(RedeemError::Unavailable)?;
                (
                    claim.device_public_key.clone(),
                    claim.endpoint_id.clone(),
                    claim.auth_epoch,
                    true,
                    enrollment_key.is_some_and(|v| v == claim.idempotency_key),
                )
            } else {
                return Err(RedeemError::Unavailable);
            }
        };
        if expected_endpoint != authenticated_client_endpoint_id
            || current_epoch != challenge.auth_epoch
            || !can_revoke
            || !enrollment_matches
        {
            return Err(RedeemError::Unavailable);
        }
        verify_request_signature(
            request,
            challenge,
            proof,
            host_endpoint_id,
            authenticated_client_endpoint_id,
            &public_key,
        )?;
        self.record_fresh_client_nonce(credential_id, request.client_nonce())
            .await?;
        let operation_gate = self
            .credential_operation_gate(credential_id)
            .await
            .write_owned()
            .await;

        let fingerprint = hex::encode(request.operation_payload_hash());
        let operation_key = format!(
            "{}:{}:{}",
            credential_id,
            request.operation(),
            idempotency_key
        );
        let mut guard = self.state.lock().await;
        let state_is_durable = match self.confirm_current_state_durability(&guard).await {
            Ok(()) => true,
            Err(error) => {
                error!("pairing-store durability retry failed before revocation commit: {error:#}");
                false
            }
        };
        if let Some(existing) = guard.operations.get(&operation_key) {
            if existing.fingerprint != fingerprint {
                return Err(RedeemError::Unavailable);
            }
            let receipt = existing.receipt.clone();
            let outcome = if state_is_durable {
                RevocationMutationV2::Durable(receipt)
            } else {
                RevocationMutationV2::OutcomeUnknown(receipt)
            };
            drop(guard);
            drop(operation_gate);
            self.remove_operation_gate_if_idle(credential_id).await;
            return Ok(outcome);
        }
        if !state_is_durable {
            return Err(RedeemError::DurabilityUnknown);
        }
        let authority_is_current = if let Some(device) = guard.devices.get(credential_id) {
            device.revoked_at.is_none()
                && device.endpoint_id == authenticated_client_endpoint_id
                && device.auth_epoch == challenge.auth_epoch
                && device.granted_scopes.contains(&DeviceScopeV2::SelfRevoke)
                && enrollment_key.is_none_or(|key| {
                    find_claim_by_credential(&guard, credential_id)
                        .is_some_and(|(_, claim)| claim.idempotency_key == key)
                })
        } else if rollback {
            find_claim_by_credential(&guard, credential_id).is_some_and(|(_, claim)| {
                claim.status == ClaimStatus::Pending
                    && claim.endpoint_id == authenticated_client_endpoint_id
                    && claim.auth_epoch == challenge.auth_epoch
                    && enrollment_key.is_some_and(|key| key == claim.idempotency_key)
            })
        } else {
            false
        };
        if !authority_is_current {
            return Err(RedeemError::Unavailable);
        }
        if guard
            .devices
            .get(credential_id)
            .is_some_and(|device| device.revoked_at.is_some())
        {
            // A revoked credential may replay only its already-committed
            // receipt. New operation ids would otherwise grow durable state
            // forever after authority has ended.
            return Err(RedeemError::Unavailable);
        }
        let mut next = guard.clone();
        let new_epoch = if let Some(device) = next.devices.get_mut(credential_id) {
            if device.revoked_at.is_none() {
                device.auth_epoch = device.auth_epoch.saturating_add(1);
                device.revoked_at = Some(now);
            }
            device.auth_epoch
        } else {
            let invitation_id = find_claim_by_credential(&next, credential_id)
                .map(|(id, _)| id.to_string())
                .ok_or(RedeemError::Unavailable)?;
            let invitation = next
                .invitations
                .get_mut(&invitation_id)
                .expect("claim exists");
            let claim = invitation.claim.as_mut().expect("claim exists");
            if claim.status != ClaimStatus::Pending {
                return Err(RedeemError::Unavailable);
            }
            claim.auth_epoch = claim.auth_epoch.saturating_add(1);
            claim.status = ClaimStatus::RolledBack;
            invitation.terminal_at = Some(now);
            claim.auth_epoch
        };
        if rollback && let Some((invitation_id, _)) = find_claim_by_credential(&next, credential_id)
        {
            let invitation_id = invitation_id.to_string();
            let invitation = next
                .invitations
                .get_mut(&invitation_id)
                .expect("claim exists");
            if let Some(claim) = invitation.claim.as_mut() {
                claim.status = ClaimStatus::RolledBack;
                claim.auth_epoch = new_epoch;
            }
            invitation.terminal_at = Some(now);
        }
        let receipt = RevocationReceiptV2 {
            credential_id: credential_id.to_string(),
            auth_epoch: new_epoch,
            revoked_at: now,
            idempotency_key: idempotency_key.to_string(),
        };
        next.operations.insert(
            operation_key,
            OperationReceiptRecord {
                fingerprint,
                receipt: receipt.clone(),
                created_at: now,
            },
        );
        let durability = match self.commit_state(&mut guard, next).await {
            Ok(durability) => durability,
            Err(error) => {
                error!("persisting pairing revocation failed before commit: {error:#}");
                return Err(RedeemError::Unavailable);
            }
        };
        let outcome = match durability {
            CommitDurability::Durable => Ok(RevocationMutationV2::Durable(receipt)),
            CommitDurability::CommittedUnknown(error) => {
                error!("pairing revocation committed with unknown directory durability: {error:#}");
                Ok(RevocationMutationV2::OutcomeUnknown(receipt))
            }
        };
        drop(operation_gate);
        self.remove_operation_gate_if_idle(credential_id).await;
        outcome
    }

    async fn record_fresh_client_nonce(
        &self,
        credential_id: &str,
        client_nonce: &str,
    ) -> Result<(), RedeemError> {
        let mut replay = self.recent_client_nonces.lock().await;
        if !replay.record(credential_id, client_nonce) {
            return Err(RedeemError::Unavailable);
        }
        Ok(())
    }

    pub async fn list_devices(&self) -> Vec<DeviceSummary> {
        let guard = self.state.lock().await;
        let mut devices: Vec<_> = guard.devices.values().map(DeviceRecord::summary).collect();
        devices.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.device_id.cmp(&b.device_id))
        });
        devices
    }

    pub async fn revoke_device(&self, device_id: &str) -> anyhow::Result<Option<DeviceSummary>> {
        let now = unix_now();
        {
            let state = self.state.lock().await;
            self.confirm_current_state_durability(&state).await?;
            if !state.devices.contains_key(device_id) {
                return Ok(None);
            }
        }
        let operation_gate = self
            .credential_operation_gate(device_id)
            .await
            .write_owned()
            .await;
        let (summary, durability) = {
            let mut guard = self.state.lock().await;
            self.confirm_current_state_durability(&guard).await?;
            let Some(current) = guard.devices.get(device_id) else {
                drop(guard);
                drop(operation_gate);
                self.remove_operation_gate_if_idle(device_id).await;
                return Ok(None);
            };
            if current.revoked_at.is_some() {
                let summary = current.summary();
                drop(guard);
                drop(operation_gate);
                self.terminate_credential_sessions(device_id).await;
                self.remove_operation_gate_if_idle(device_id).await;
                return Ok(Some(summary));
            }
            let mut next = guard.clone();
            let device = next.devices.get_mut(device_id).expect("device exists");
            device.auth_epoch = device.auth_epoch.saturating_add(1);
            device.revoked_at = Some(now);
            let summary = device.summary();
            let durability = self.commit_state(&mut guard, next).await?;
            (summary, durability)
        };
        drop(operation_gate);
        self.terminate_credential_sessions(device_id).await;
        self.remove_operation_gate_if_idle(device_id).await;
        match durability {
            CommitDurability::Durable => Ok(Some(summary)),
            CommitDurability::CommittedUnknown(error) => Err(error
                .context("device revocation was committed but directory durability is unknown")),
        }
    }

    pub async fn register_authenticated_connection(
        &self,
        authorization: &AuthorizationContextV2,
        authenticated_client_endpoint_id: &str,
        connection: Connection,
    ) -> bool {
        // Hold the grant read lock until the connection is visible to the
        // revocation registry. This closes the authorize -> register race:
        // either revocation happens first and registration fails, or it
        // happens second and closes the newly registered connection.
        let state = self.state.lock().await;
        if self.confirm_current_state_durability(&state).await.is_err() {
            return false;
        }
        let Some(device) = state.devices.get(&authorization.credential_id) else {
            return false;
        };
        if !authorization_matches_device(authorization, authenticated_client_endpoint_id, device) {
            return false;
        }
        let mut active = self.active.lock().await;
        let connections = active
            .entry(authorization.credential_id.clone())
            .or_default();
        let stable_id = connection.stable_id();
        if !active_connection_capacity_allows(
            connections.iter().map(Connection::stable_id),
            stable_id,
        ) {
            return false;
        }
        if connections.iter().all(|v| v.stable_id() != stable_id) {
            connections.push(connection);
        }
        true
    }

    pub async fn unregister_authenticated_connection(&self, credential_id: &str, stable_id: usize) {
        let mut active = self.active.lock().await;
        if let Some(connections) = active.get_mut(credential_id) {
            connections.retain(|v| v.stable_id() != stable_id);
            if connections.is_empty() {
                active.remove(credential_id);
            }
        }
    }

    pub async fn unregister_connection_stable_id(&self, stable_id: usize) {
        let mut active = self.active.lock().await;
        active.retain(|_, connections| {
            connections.retain(|v| v.stable_id() != stable_id);
            !connections.is_empty()
        });
    }

    pub async fn is_authorization_current(
        &self,
        authorization: &AuthorizationContextV2,
        authenticated_client_endpoint_id: &str,
    ) -> bool {
        let state = self.state.lock().await;
        if self.confirm_current_state_durability(&state).await.is_err() {
            return false;
        }
        state
            .devices
            .get(&authorization.credential_id)
            .is_some_and(|device| {
                authorization_matches_device(
                    authorization,
                    authenticated_client_endpoint_id,
                    device,
                )
            })
    }

    /// Close every registered connection authenticated by one credential.
    /// Host-side revocation calls this immediately after the durable commit.
    pub async fn terminate_credential_sessions(&self, credential_id: &str) {
        self.close_connections(credential_id).await;
    }

    /// Close a revoked credential's other connections while retaining the
    /// stream that must flush the self-revocation response. The host closes
    /// that final connection after the response frame is finished.
    pub async fn terminate_credential_sessions_except(
        &self,
        credential_id: &str,
        current_stable_id: usize,
    ) {
        let removed = {
            let mut active = self.active.lock().await;
            let mut removed = Vec::new();
            let mut remove_entry = false;
            if let Some(connections) = active.get_mut(credential_id) {
                let mut retained = Vec::with_capacity(1);
                for connection in connections.drain(..) {
                    if retain_requesting_revocation_connection(
                        connection.stable_id(),
                        current_stable_id,
                    ) {
                        retained.push(connection);
                    } else {
                        removed.push(connection);
                    }
                }
                *connections = retained;
                remove_entry = connections.is_empty();
            }
            if remove_entry {
                active.remove(credential_id);
            }
            removed
        };
        for connection in removed {
            connection.close(VarInt::from_u32(0x21), b"device revoked");
        }
    }

    async fn credential_operation_gate(&self, credential_id: &str) -> Arc<RwLock<()>> {
        let mut gates = self.operation_gates.lock().await;
        gates
            .entry(credential_id.to_string())
            .or_insert_with(|| Arc::new(RwLock::new(())))
            .clone()
    }

    async fn remove_operation_gate_if_idle(&self, credential_id: &str) {
        let mut gates = self.operation_gates.lock().await;
        if gates
            .get(credential_id)
            .is_some_and(|gate| Arc::strong_count(gate) == 1)
        {
            gates.remove(credential_id);
        }
    }

    async fn close_connections(&self, credential_id: &str) {
        let connections = self
            .active
            .lock()
            .await
            .remove(credential_id)
            .unwrap_or_default();
        for connection in connections {
            connection.close(VarInt::from_u32(0x21), b"device revoked");
        }
    }

    async fn commit_state(
        &self,
        current: &mut PersistedState,
        next: PersistedState,
    ) -> anyhow::Result<CommitDurability> {
        let durability = self.persist(&next).await?;
        *current = next;
        self.durability_unknown.store(
            matches!(&durability, CommitDurability::CommittedUnknown(_)),
            Ordering::Release,
        );
        Ok(durability)
    }

    async fn retry_unknown_durability(
        &self,
        current: &PersistedState,
    ) -> anyhow::Result<CommitDurability> {
        if !self.durability_unknown.load(Ordering::Acquire) {
            return Ok(CommitDurability::Durable);
        }
        let durability = self.persist(current).await?;
        self.durability_unknown.store(
            matches!(&durability, CommitDurability::CommittedUnknown(_)),
            Ordering::Release,
        );
        Ok(durability)
    }

    async fn confirm_current_state_durability(
        &self,
        current: &PersistedState,
    ) -> anyhow::Result<()> {
        match self.retry_unknown_durability(current).await? {
            CommitDurability::Durable => Ok(()),
            CommitDurability::CommittedUnknown(error) => {
                Err(error
                    .context("pairing state remains committed with unknown directory durability"))
            }
        }
    }

    async fn persist(&self, state: &PersistedState) -> anyhow::Result<CommitDurability> {
        let bytes = serde_json::to_vec_pretty(state).context("serializing pairing store")?;
        atomic_write(&self.path, &bytes).await
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedState {
    version: u32,
    #[serde(default)]
    invitations: BTreeMap<String, InvitationRecord>,
    #[serde(default)]
    devices: BTreeMap<String, DeviceRecord>,
    #[serde(default)]
    tombstones: BTreeMap<String, InvitationTombstone>,
    #[serde(default)]
    operations: BTreeMap<String, OperationReceiptRecord>,
    #[serde(default)]
    restart_commands: BTreeMap<String, RestartCommandRecord>,
    #[serde(default)]
    restart_high_watermarks: BTreeMap<String, u64>,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            invitations: BTreeMap::new(),
            devices: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            operations: BTreeMap::new(),
            restart_commands: BTreeMap::new(),
            restart_high_watermarks: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct InvitationRecord {
    invitation_id: String,
    secret_hash: String,
    created_at: i64,
    expires_at: i64,
    max_runtime_ids: Vec<String>,
    max_scopes: Vec<DeviceScopeV2>,
    confirmation_mode: ConfirmationModeV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claim: Option<EnrollmentClaimRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ClaimStatus {
    Pending,
    Approved,
    Rejected,
    RolledBack,
}

#[derive(Clone, Serialize, Deserialize)]
struct EnrollmentClaimRecord {
    claim_id: String,
    credential_id: String,
    idempotency_key: String,
    request_fingerprint: String,
    endpoint_id: String,
    device_public_key: String,
    display_name: String,
    selected_runtime_ids: Vec<String>,
    requested_scopes: Vec<DeviceScopeV2>,
    sas: String,
    transcript_hash: String,
    created_at: i64,
    expires_at: i64,
    auth_epoch: u64,
    status: ClaimStatus,
}

impl EnrollmentClaimRecord {
    fn pending(&self) -> PendingEnrollmentV2 {
        PendingEnrollmentV2 {
            claim_id: self.claim_id.clone(),
            credential_id: self.credential_id.clone(),
            display_name: self.display_name.clone(),
            selected_runtime_ids: self.selected_runtime_ids.clone(),
            requested_scopes: self.requested_scopes.clone(),
            enrollment_confirmation: self.confirmation(),
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }
    fn summary(&self) -> PendingPairingSummary {
        PendingPairingSummary {
            claim_id: self.claim_id.clone(),
            credential_id: self.credential_id.clone(),
            display_name: self.display_name.clone(),
            endpoint_fingerprint: endpoint_fingerprint(&self.endpoint_id),
            device_key_fingerprint: device_key_fingerprint(&self.device_public_key),
            selected_runtime_ids: self.selected_runtime_ids.clone(),
            requested_scopes: self.requested_scopes.clone(),
            sas: self.sas.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }

    fn confirmation(&self) -> EnrollmentConfirmationV2 {
        EnrollmentConfirmationV2 {
            transcript_hash: self.transcript_hash.clone(),
            sas: self.sas.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct DeviceRecord {
    device_id: String,
    endpoint_id: String,
    device_public_key: String,
    display_name: String,
    selected_runtime_ids: Vec<String>,
    granted_scopes: Vec<DeviceScopeV2>,
    auth_epoch: u64,
    created_at: i64,
    enrollment_confirmation: EnrollmentConfirmationV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revoked_at: Option<i64>,
}

impl DeviceRecord {
    fn from_claim(claim: &EnrollmentClaimRecord, now: i64) -> Self {
        Self {
            device_id: claim.credential_id.clone(),
            endpoint_id: claim.endpoint_id.clone(),
            device_public_key: claim.device_public_key.clone(),
            display_name: claim.display_name.clone(),
            selected_runtime_ids: claim.selected_runtime_ids.clone(),
            granted_scopes: claim.requested_scopes.clone(),
            auth_epoch: claim.auth_epoch,
            created_at: now,
            enrollment_confirmation: claim.confirmation(),
            revoked_at: None,
        }
    }
    fn enrolled(&self) -> EnrolledDevice {
        EnrolledDevice {
            device_id: self.device_id.clone(),
            display_name: self.display_name.clone(),
            endpoint_fingerprint: endpoint_fingerprint(&self.endpoint_id),
            device_key_fingerprint: device_key_fingerprint(&self.device_public_key),
            selected_runtime_ids: self.selected_runtime_ids.clone(),
            granted_scopes: self.granted_scopes.clone(),
            auth_epoch: self.auth_epoch,
            created_at: self.created_at,
            enrollment_confirmation: self.enrollment_confirmation.clone(),
        }
    }
    fn summary(&self) -> DeviceSummary {
        DeviceSummary {
            device_id: self.device_id.clone(),
            display_name: self.display_name.clone(),
            endpoint_fingerprint: endpoint_fingerprint(&self.endpoint_id),
            device_key_fingerprint: device_key_fingerprint(&self.device_public_key),
            selected_runtime_ids: self.selected_runtime_ids.clone(),
            granted_scopes: self.granted_scopes.clone(),
            auth_epoch: self.auth_epoch,
            state: if self.revoked_at.is_some() {
                GrantStateV2::Revoked
            } else {
                GrantStateV2::Active
            },
            created_at: self.created_at,
            revoked_at: self.revoked_at,
        }
    }
    fn authorization(&self) -> AuthorizationContextV2 {
        AuthorizationContextV2 {
            credential_id: self.device_id.clone(),
            auth_epoch: self.auth_epoch,
            selected_runtime_ids: self.selected_runtime_ids.clone(),
            granted_scopes: self.granted_scopes.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct InvitationTombstone {
    invitation_id: String,
    consumed_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct OperationReceiptRecord {
    fingerprint: String,
    receipt: RevocationReceiptV2,
    created_at: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RestartCommandStatus {
    Prepared,
    Succeeded,
}

#[derive(Clone, Serialize, Deserialize)]
struct RestartCommandRecord {
    command_id: String,
    credential_id: String,
    idempotency_key: String,
    command_sequence: u64,
    request_fingerprint: String,
    agent: String,
    auth_epoch: u64,
    status: RestartCommandStatus,
    created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    succeeded_at: Option<i64>,
}

impl RestartCommandRecord {
    fn result(&self) -> RestartResultV2 {
        RestartResultV2 {
            agent: self.agent.clone(),
            idempotency_key: self.idempotency_key.clone(),
            command_sequence: self.command_sequence,
            status: match self.status {
                RestartCommandStatus::Prepared => RestartStatusV2::OutcomeUnknown,
                RestartCommandStatus::Succeeded => RestartStatusV2::Succeeded,
            },
        }
    }
}

fn claim_outcome(
    state: &PersistedState,
    claim: &EnrollmentClaimRecord,
) -> Result<EnrollmentOutcomeV2, RedeemError> {
    match claim.status {
        ClaimStatus::Pending => Ok(EnrollmentOutcomeV2::Pending {
            pending: claim.pending(),
        }),
        ClaimStatus::Approved => state
            .devices
            .get(&claim.credential_id)
            .map(|v| EnrollmentOutcomeV2::Enrolled {
                enrolled: v.enrolled(),
            })
            .ok_or(RedeemError::Unavailable),
        ClaimStatus::Rejected | ClaimStatus::RolledBack => Err(RedeemError::Unavailable),
    }
}

fn find_invitation_id_by_claim(state: &PersistedState, claim_id: &str) -> Option<String> {
    state.invitations.iter().find_map(|(id, invitation)| {
        invitation
            .claim
            .as_ref()
            .filter(|v| v.claim_id == claim_id)
            .map(|_| id.clone())
    })
}

fn find_claim_by_credential<'a>(
    state: &'a PersistedState,
    credential_id: &str,
) -> Option<(&'a str, &'a EnrollmentClaimRecord)> {
    state.invitations.iter().find_map(|(id, invitation)| {
        invitation
            .claim
            .as_ref()
            .filter(|v| v.credential_id == credential_id)
            .map(|claim| (id.as_str(), claim))
    })
}

fn sanitize_loaded_invitations(state: &mut PersistedState, now: i64) {
    for invitation in state.invitations.values_mut() {
        let issued = invitation.claim.is_none() && invitation.terminal_at.is_none();
        let pending = invitation
            .claim
            .as_ref()
            .is_some_and(|claim| claim.status == ClaimStatus::Pending);
        if !issued && !pending {
            continue;
        }
        let maximum_lifetime = match invitation.confirmation_mode {
            ConfirmationModeV2::Interactive => DEFAULT_INVITATION_TTL.as_secs() as i64,
            ConfirmationModeV2::Unattended => MAX_UNATTENDED_INVITATION_TTL.as_secs() as i64,
        };
        let invalid_lifetime = invitation
            .expires_at
            .checked_sub(invitation.created_at)
            .is_none_or(|lifetime| lifetime <= 0 || lifetime > maximum_lifetime);
        let invalid_envelope = now < invitation.created_at || invalid_lifetime;
        let invalid_claim = invitation.claim.as_ref().is_some_and(|claim| {
            claim.created_at < invitation.created_at
                || claim.created_at >= invitation.expires_at
                || claim.expires_at != invitation.expires_at
        });
        if invalid_envelope || invalid_claim {
            if let Some(claim) = invitation.claim.as_mut()
                && claim.status == ClaimStatus::Pending
            {
                claim.status = ClaimStatus::Rejected;
            }
            invitation.terminal_at = Some(now);
        }
    }
}

fn sweep_expired(state: &mut PersistedState, now: i64) {
    let ids: Vec<_> = state.invitations.keys().cloned().collect();
    for id in ids {
        let Some(invitation) = state.invitations.get_mut(&id) else {
            continue;
        };
        if invitation.expires_at <= now && invitation.terminal_at.is_none() {
            if let Some(claim) = invitation.claim.as_mut()
                && claim.status == ClaimStatus::Pending
            {
                claim.status = ClaimStatus::Rejected;
            }
            invitation.terminal_at = Some(now);
        }
        if invitation
            .terminal_at
            .is_some_and(|at| at <= now - TOMBSTONE_RETENTION_SECS)
        {
            terminalize_invitation(state, &id, now);
        }
    }
    state
        .tombstones
        .retain(|_, v| v.consumed_at > now - TOMBSTONE_RETENTION_SECS);
    state
        .operations
        .retain(|_, v| v.created_at > now - TOMBSTONE_RETENTION_SECS);
}

fn terminalize_invitation(state: &mut PersistedState, invitation_id: &str, now: i64) {
    if let Some(invitation) = state.invitations.remove(invitation_id) {
        state.tombstones.insert(
            invitation_id.to_string(),
            InvitationTombstone {
                invitation_id: invitation_id.to_string(),
                consumed_at: now,
                device_id: invitation.claim.map(|v| v.credential_id),
            },
        );
    }
}

fn unique_invitation_id(state: &PersistedState) -> String {
    loop {
        let id = random_urlsafe(INVITATION_ID_BYTES);
        if !state.invitations.contains_key(&id) && !state.tombstones.contains_key(&id) {
            return id;
        }
    }
}

fn unique_claim_id(state: &PersistedState) -> String {
    loop {
        let id = random_urlsafe(CLAIM_ID_BYTES);
        if state
            .invitations
            .values()
            .all(|v| v.claim.as_ref().is_none_or(|c| c.claim_id != id))
        {
            return id;
        }
    }
}

fn prospective_credential_id(
    invitation_id: &str,
    authenticated_client_endpoint_id: &str,
    device_public_key: &str,
    idempotency_key: &str,
) -> Result<String, RedeemError> {
    let mut encoded = Vec::with_capacity(512);
    encoded.extend_from_slice(PROSPECTIVE_CREDENTIAL_DOMAIN);
    for field in [
        invitation_id.as_bytes(),
        authenticated_client_endpoint_id.as_bytes(),
        device_public_key.as_bytes(),
        idempotency_key.as_bytes(),
    ] {
        append_field(&mut encoded, field).map_err(|_| RedeemError::Unavailable)?;
    }
    let digest = Sha256::digest(&encoded);
    encoded.zeroize();
    Ok(URL_SAFE_NO_PAD.encode(&digest[..DEVICE_ID_BYTES]))
}

fn unique_restart_command_id(state: &PersistedState) -> String {
    loop {
        let id = random_urlsafe(CHALLENGE_ID_BYTES);
        if state
            .restart_commands
            .values()
            .all(|command| command.command_id != id)
        {
            return id;
        }
    }
}

fn restart_journal_key(credential_id: &str, command_sequence: u64) -> String {
    format!("{credential_id}:restart:{command_sequence:020}")
}

fn random_urlsafe(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn pairing_invitation_json(invitation: &PairingInvitation) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let json =
        Zeroizing::new(serde_json::to_vec(invitation).context("serializing pairing invitation")?);
    let full_groups = json.len() / 3;
    let remainder = json.len() % 3;
    let encoded_len = full_groups
        .checked_mul(4)
        .and_then(|length| length.checked_add(if remainder == 0 { 0 } else { remainder + 1 }))
        .ok_or_else(|| anyhow!("pairing invitation is too large"))?;
    if encoded_len > MAX_PAIRING_CODE_SEGMENT_BYTES {
        return Err(anyhow!("pairing invitation is too large"));
    }
    Ok(json)
}

fn valid_opaque_id(value: &str) -> bool {
    value.len() == 22
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || v == b'-' || v == b'_')
}

fn valid_label(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn valid_idempotency_key(value: &str) -> bool {
    valid_label(value, MAX_IDEMPOTENCY_KEY_BYTES)
}

fn valid_runtime_id(value: &str) -> bool {
    valid_label(value, MAX_RUNTIME_ID_BYTES)
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_' | b'.' | b'/'))
}

fn canonicalize_runtime_ids(values: &mut Vec<String>) -> anyhow::Result<()> {
    if values.is_empty()
        || values.len() > MAX_RUNTIME_IDS
        || values.iter().any(|v| !valid_runtime_id(v))
    {
        return Err(anyhow!("invalid runtime selection"));
    }
    values.sort();
    values.dedup();
    Ok(())
}

fn canonicalize_scopes(values: &mut Vec<DeviceScopeV2>) -> anyhow::Result<()> {
    if values.is_empty() || values.len() > 4 {
        return Err(anyhow!("invalid scope selection"));
    }
    values.sort();
    values.dedup();
    Ok(())
}

fn canonical_runtime_ids(values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    values.join("\0")
}

fn canonical_scopes(values: &[DeviceScopeV2]) -> String {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    values
        .into_iter()
        .map(|v| match v {
            DeviceScopeV2::InspectRuntimes => "inspect_runtimes",
            DeviceScopeV2::ConnectRuntime => "connect_runtime",
            DeviceScopeV2::RestartRuntime => "restart_runtime",
            DeviceScopeV2::SelfRevoke => "self_revoke",
        })
        .collect::<Vec<_>>()
        .join("\0")
}

fn validate_policy(
    runtime_ids: &[String],
    scopes: &[DeviceScopeV2],
    mode: ConfirmationModeV2,
    ttl: Duration,
) -> anyhow::Result<()> {
    validate_policy_shape(runtime_ids, scopes, mode)?;
    if mode == ConfirmationModeV2::Interactive {
        if ttl.is_zero() || ttl > DEFAULT_INVITATION_TTL {
            return Err(anyhow!("interactive invitation ttl exceeds 5 minutes"));
        }
    } else if ttl.is_zero() || ttl > MAX_UNATTENDED_INVITATION_TTL {
        return Err(anyhow!("unattended invitation ttl exceeds 60 seconds"));
    }
    Ok(())
}

fn validate_policy_shape(
    runtime_ids: &[String],
    scopes: &[DeviceScopeV2],
    mode: ConfirmationModeV2,
) -> anyhow::Result<()> {
    let mut runtimes = runtime_ids.to_vec();
    let original_scopes = scopes;
    let mut canonical_scope_values = scopes.to_vec();
    canonicalize_runtime_ids(&mut runtimes)?;
    canonicalize_scopes(&mut canonical_scope_values)?;
    if runtimes != runtime_ids || canonical_scope_values != original_scopes {
        return Err(anyhow!("invitation policy must be canonical"));
    }
    validate_grant(&runtimes, &canonical_scope_values)
        .map_err(|_| anyhow!("invalid invitation policy"))?;
    if mode == ConfirmationModeV2::Unattended
        && (runtimes.len() != 1
            || canonical_scope_values.contains(&DeviceScopeV2::RestartRuntime)
            || canonical_scope_values
                != vec![
                    DeviceScopeV2::InspectRuntimes,
                    DeviceScopeV2::ConnectRuntime,
                    DeviceScopeV2::SelfRevoke,
                ])
    {
        return Err(anyhow!(
            "unattended invitations require one runtime and narrow scopes"
        ));
    }
    Ok(())
}

fn validate_grant(runtime_ids: &[String], scopes: &[DeviceScopeV2]) -> Result<(), RedeemError> {
    let mut runtimes = runtime_ids.to_vec();
    let original_scopes = scopes;
    let mut canonical_scope_values = scopes.to_vec();
    canonicalize_runtime_ids(&mut runtimes).map_err(|_| RedeemError::Unavailable)?;
    canonicalize_scopes(&mut canonical_scope_values).map_err(|_| RedeemError::Unavailable)?;
    if runtimes != runtime_ids
        || canonical_scope_values != original_scopes
        || !canonical_scope_values.contains(&DeviceScopeV2::ConnectRuntime)
        || !canonical_scope_values.contains(&DeviceScopeV2::SelfRevoke)
    {
        return Err(RedeemError::Unavailable);
    }
    Ok(())
}

fn ensure_subset(values: &[String], maximum: &[String]) -> Result<(), RedeemError> {
    let original = values;
    let mut canonical = values.to_vec();
    canonicalize_runtime_ids(&mut canonical).map_err(|_| RedeemError::Unavailable)?;
    if canonical == original && canonical.iter().all(|v| maximum.contains(v)) {
        Ok(())
    } else {
        Err(RedeemError::Unavailable)
    }
}

fn ensure_scope_subset(
    values: &[DeviceScopeV2],
    maximum: &[DeviceScopeV2],
) -> Result<(), RedeemError> {
    let original = values;
    let mut canonical = values.to_vec();
    canonicalize_scopes(&mut canonical).map_err(|_| RedeemError::Unavailable)?;
    if canonical == original && canonical.iter().all(|v| maximum.contains(v)) {
        Ok(())
    } else {
        Err(RedeemError::Unavailable)
    }
}

fn validate_request(request: &RequestV2) -> Result<(), RedeemError> {
    if request.version() != PROTOCOL_VERSION_V2 || decode_nonce(request.client_nonce()).is_none() {
        return Err(RedeemError::Unavailable);
    }
    match request {
        RequestV2::InspectInvitation {
            invitation_id,
            secret,
            device_public_key,
            ..
        } => {
            if !valid_opaque_id(invitation_id)
                || secret.len() > 128
                || parse_device_public_key(device_public_key).is_err()
            {
                return Err(RedeemError::Unavailable);
            }
        }
        RequestV2::Enroll {
            invitation_id,
            secret,
            device_name,
            device_public_key,
            selected_runtime_ids,
            requested_scopes,
            idempotency_key,
            ..
        } => {
            if !valid_opaque_id(invitation_id)
                || secret.len() > 128
                || (!device_name.is_empty()
                    && (device_name.len() > MAX_DEVICE_NAME_BYTES
                        || device_name.chars().any(char::is_control)))
                || parse_device_public_key(device_public_key).is_err()
                || !valid_idempotency_key(idempotency_key)
                || validate_grant(selected_runtime_ids, requested_scopes).is_err()
            {
                return Err(RedeemError::Unavailable);
            }
        }
        RequestV2::ListAgents { credential_id, .. }
        | RequestV2::CommandCenterStatus { credential_id, .. } => {
            if !valid_opaque_id(credential_id) {
                return Err(RedeemError::Unavailable);
            }
        }
        RequestV2::RestartAgent {
            credential_id,
            agent,
            idempotency_key,
            command_sequence,
            ..
        } => {
            if !valid_opaque_id(credential_id)
                || !valid_runtime_id(agent)
                || !valid_idempotency_key(idempotency_key)
                || *command_sequence == 0
            {
                return Err(RedeemError::Unavailable);
            }
        }
        RequestV2::Connect {
            credential_id,
            agent,
            ..
        } => {
            if !valid_opaque_id(credential_id) || !valid_runtime_id(agent) {
                return Err(RedeemError::Unavailable);
            }
        }
        RequestV2::RevokeSelf {
            credential_id,
            idempotency_key,
            ..
        } => {
            if !valid_opaque_id(credential_id) || !valid_idempotency_key(idempotency_key) {
                return Err(RedeemError::Unavailable);
            }
        }
        RequestV2::RollbackEnrollment {
            credential_id,
            enrollment_idempotency_key,
            idempotency_key,
            ..
        } => {
            if !valid_opaque_id(credential_id)
                || !valid_idempotency_key(enrollment_idempotency_key)
                || !valid_idempotency_key(idempotency_key)
            {
                return Err(RedeemError::Unavailable);
            }
        }
    }
    Ok(())
}

fn enforce_operation_grant(request: &RequestV2, device: &DeviceRecord) -> Result<(), RedeemError> {
    let (scope, runtime) = match request {
        RequestV2::ListAgents { .. } | RequestV2::CommandCenterStatus { .. } => {
            (DeviceScopeV2::InspectRuntimes, None)
        }
        RequestV2::RestartAgent { agent, .. } => (DeviceScopeV2::RestartRuntime, Some(agent)),
        RequestV2::Connect { agent, .. } => (DeviceScopeV2::ConnectRuntime, Some(agent)),
        _ => return Err(RedeemError::Unavailable),
    };
    if !device.granted_scopes.contains(&scope)
        || runtime.is_some_and(|v| !device.selected_runtime_ids.contains(v))
    {
        return Err(RedeemError::Unavailable);
    }
    Ok(())
}

fn authorization_matches_device(
    authorization: &AuthorizationContextV2,
    authenticated_client_endpoint_id: &str,
    device: &DeviceRecord,
) -> bool {
    device.revoked_at.is_none()
        && device.endpoint_id == authenticated_client_endpoint_id
        && device.auth_epoch == authorization.auth_epoch
        && device.selected_runtime_ids == authorization.selected_runtime_ids
        && device.granted_scopes == authorization.granted_scopes
}

fn active_connection_capacity_allows(
    existing: impl IntoIterator<Item = usize>,
    candidate: usize,
) -> bool {
    let mut count = 0;
    for stable_id in existing {
        if stable_id == candidate {
            return true;
        }
        count += 1;
    }
    count < MAX_ACTIVE_CONNECTIONS_PER_CREDENTIAL
}

fn retain_requesting_revocation_connection(candidate: usize, requesting: usize) -> bool {
    candidate == requesting
}

fn invitation_secret_hash(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SECRET_HASH_DOMAIN);
    let mut decoded = URL_SAFE_NO_PAD.decode(secret).unwrap_or_default();
    hasher.update(&decoded);
    decoded.zeroize();
    hasher.finalize().into()
}

fn secret_hash_matches(expected_hex: &str, candidate: &str) -> bool {
    let Ok(expected) = hex::decode(expected_hex) else {
        return false;
    };
    let actual = invitation_secret_hash(candidate);
    expected.len() == actual.len() && bool::from(expected.as_slice().ct_eq(actual.as_slice()))
}

fn endpoint_fingerprint(endpoint_id: &str) -> String {
    hex::encode(&Sha256::digest(endpoint_id.as_bytes())[..8])
}

fn device_key_fingerprint(device_public_key: &str) -> String {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(device_public_key) else {
        return "invalid".to_string();
    };
    hex::encode(&Sha256::digest(bytes)[..8])
}

fn parse_device_public_key(value: &str) -> anyhow::Result<(VerifyingKey, Vec<u8>)> {
    if value.len() > 128 {
        return Err(anyhow!("device public key is too large"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .context("decoding device public key")?;
    if bytes.len() != 65 || bytes.first() != Some(&0x04) {
        return Err(anyhow!("device public key must be uncompressed P-256 SEC1"));
    }
    let key = VerifyingKey::from_sec1_bytes(&bytes).context("parsing P-256 device public key")?;
    Ok((key, bytes))
}

fn decode_nonce(value: &str) -> Option<[u8; NONCE_BYTES]> {
    if value.len() > 64 {
        return None;
    }
    URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()
}

fn validate_challenge_proof(
    challenge: &ProofChallengeV2,
    proof: &ProofV2,
    now: i64,
) -> Result<(), RedeemError> {
    if proof.v != PROTOCOL_VERSION_V2
        || proof.challenge_id != challenge.challenge_id
        || challenge.expires_at < now
        || challenge.expires_at > now.saturating_add(CHALLENGE_TTL.as_secs() as i64)
        || !valid_opaque_id(&challenge.challenge_id)
        || !valid_opaque_id(&challenge.credential_id)
        || decode_nonce(&challenge.server_nonce).is_none()
        || proof.signature.len() > 128
    {
        return Err(RedeemError::Unavailable);
    }
    Ok(())
}

fn verify_request_signature(
    request: &RequestV2,
    challenge: &ProofChallengeV2,
    proof: &ProofV2,
    host_endpoint_id: &str,
    client_endpoint_id: &str,
    public_key: &str,
) -> Result<(), RedeemError> {
    let (verifying_key, key_bytes) =
        parse_device_public_key(public_key).map_err(|_| RedeemError::Unavailable)?;
    let key_hash = Sha256::digest(&key_bytes).into();
    let transcript = encode_proof_transcript(&ProofTranscript {
        host_endpoint_id,
        client_endpoint_id,
        operation: request.operation(),
        credential_id: &challenge.credential_id,
        auth_epoch: challenge.auth_epoch,
        device_key_hash: &key_hash,
        challenge_id: &challenge.challenge_id,
        server_nonce: &challenge.server_nonce,
        client_nonce: request.client_nonce(),
        operation_payload_hash: &request.operation_payload_hash(),
    })
    .map_err(|_| RedeemError::Unavailable)?;
    verify_signature(&verifying_key, &transcript, &proof.signature)
}

fn verify_signature(
    key: &VerifyingKey,
    transcript: &[u8],
    encoded: &str,
) -> Result<(), RedeemError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| RedeemError::Unavailable)?;
    let signature = Signature::from_der(&bytes).map_err(|_| RedeemError::Unavailable)?;
    key.verify(transcript, &signature)
        .map_err(|_| RedeemError::Unavailable)
}

pub struct ProofTranscript<'a> {
    pub host_endpoint_id: &'a str,
    pub client_endpoint_id: &'a str,
    pub operation: &'a str,
    pub credential_id: &'a str,
    pub auth_epoch: u64,
    pub device_key_hash: &'a [u8; 32],
    pub challenge_id: &'a str,
    pub server_nonce: &'a str,
    pub client_nonce: &'a str,
    pub operation_payload_hash: &'a [u8; 32],
}

pub fn encode_proof_transcript(input: &ProofTranscript<'_>) -> anyhow::Result<Vec<u8>> {
    let mut encoded = Vec::with_capacity(512);
    encoded.extend_from_slice(PROOF_TRANSCRIPT_DOMAIN);
    append_field(&mut encoded, &PROTOCOL_VERSION_V2.to_be_bytes())?;
    append_field(&mut encoded, REMORA_LINK_ALPN)?;
    append_field(&mut encoded, input.host_endpoint_id.as_bytes())?;
    append_field(&mut encoded, input.client_endpoint_id.as_bytes())?;
    append_field(&mut encoded, input.operation.as_bytes())?;
    append_field(&mut encoded, input.credential_id.as_bytes())?;
    append_field(&mut encoded, &input.auth_epoch.to_be_bytes())?;
    append_field(&mut encoded, input.device_key_hash)?;
    append_field(&mut encoded, input.challenge_id.as_bytes())?;
    append_field(&mut encoded, input.server_nonce.as_bytes())?;
    append_field(&mut encoded, input.client_nonce.as_bytes())?;
    append_field(&mut encoded, input.operation_payload_hash)?;
    Ok(encoded)
}

#[derive(Clone, Copy)]
pub struct EnrollmentTranscriptInput<'a> {
    pub host_endpoint_id: &'a str,
    pub client_endpoint_id: &'a str,
    pub invitation_id: &'a str,
    pub device_public_key: &'a str,
    pub idempotency_key: &'a str,
    pub selected_runtime_ids: &'a [String],
    pub requested_scopes: &'a [DeviceScopeV2],
    pub server_nonce: &'a str,
    pub client_nonce: &'a str,
    pub confirmation_mode: ConfirmationModeV2,
    pub max_runtime_ids: &'a [String],
    pub max_scopes: &'a [DeviceScopeV2],
}

pub fn enrollment_transcript_hash(
    input: EnrollmentTranscriptInput<'_>,
) -> anyhow::Result<[u8; 32]> {
    Ok(Sha256::digest(encode_enrollment_transcript(input)?).into())
}

pub fn encode_enrollment_transcript(
    input: EnrollmentTranscriptInput<'_>,
) -> anyhow::Result<Vec<u8>> {
    validate_grant(input.selected_runtime_ids, input.requested_scopes)
        .map_err(|_| anyhow!("invalid enrollment grant"))?;
    ensure_subset(input.selected_runtime_ids, input.max_runtime_ids)
        .map_err(|_| anyhow!("enrollment runtimes exceed host policy"))?;
    ensure_scope_subset(input.requested_scopes, input.max_scopes)
        .map_err(|_| anyhow!("enrollment scopes exceed host policy"))?;
    let (_, key_bytes) = parse_device_public_key(input.device_public_key)?;
    let mut encoded = Vec::with_capacity(768);
    encoded.extend_from_slice(ENROLLMENT_TRANSCRIPT_DOMAIN);
    append_field(&mut encoded, &PROTOCOL_VERSION_V2.to_be_bytes())?;
    append_field(&mut encoded, REMORA_LINK_ALPN)?;
    append_field(&mut encoded, input.host_endpoint_id.as_bytes())?;
    append_field(&mut encoded, input.client_endpoint_id.as_bytes())?;
    append_field(&mut encoded, input.invitation_id.as_bytes())?;
    append_field(&mut encoded, input.idempotency_key.as_bytes())?;
    append_field(&mut encoded, input.server_nonce.as_bytes())?;
    append_field(&mut encoded, input.client_nonce.as_bytes())?;
    append_field(&mut encoded, &key_bytes)?;
    append_field(
        &mut encoded,
        canonical_runtime_ids(input.selected_runtime_ids).as_bytes(),
    )?;
    append_field(
        &mut encoded,
        canonical_scopes(input.requested_scopes).as_bytes(),
    )?;
    append_field(
        &mut encoded,
        &host_policy_digest(input.max_runtime_ids, input.max_scopes)?,
    )?;
    append_field(
        &mut encoded,
        &[match input.confirmation_mode {
            ConfirmationModeV2::Interactive => 0,
            ConfirmationModeV2::Unattended => 1,
        }],
    )?;
    Ok(encoded)
}

pub fn host_policy_digest(
    max_runtime_ids: &[String],
    max_scopes: &[DeviceScopeV2],
) -> anyhow::Result<[u8; 32]> {
    Ok(Sha256::digest(encode_host_policy_transcript(max_runtime_ids, max_scopes)?).into())
}

pub fn encode_host_policy_transcript(
    max_runtime_ids: &[String],
    max_scopes: &[DeviceScopeV2],
) -> anyhow::Result<Vec<u8>> {
    let mut canonical_runtimes = max_runtime_ids.to_vec();
    let mut canonical_scope_values = max_scopes.to_vec();
    canonicalize_runtime_ids(&mut canonical_runtimes)?;
    canonicalize_scopes(&mut canonical_scope_values)?;
    if canonical_runtimes != max_runtime_ids || canonical_scope_values != max_scopes {
        return Err(anyhow!("host policy must be canonical"));
    }
    let mut encoded = Vec::with_capacity(256);
    encoded.extend_from_slice(POLICY_DIGEST_DOMAIN);
    append_field(
        &mut encoded,
        canonical_runtime_ids(max_runtime_ids).as_bytes(),
    )?;
    append_field(&mut encoded, canonical_scopes(max_scopes).as_bytes())?;
    Ok(encoded)
}

pub fn derive_sas(invitation_secret: &str, enrollment_transcript_hash: &[u8; 32]) -> String {
    let mut message = Vec::with_capacity(SAS_DOMAIN.len() + 32);
    message.extend_from_slice(SAS_DOMAIN);
    message.extend_from_slice(enrollment_transcript_hash);
    let mut secret = URL_SAFE_NO_PAD
        .decode(invitation_secret)
        .unwrap_or_default();
    let digest = hmac_sha256(&secret, &message);
    secret.zeroize();
    const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let value = u32::from_be_bytes(digest[..4].try_into().expect("four bytes")) >> 2;
    let mut code = [0_u8; 6];
    for (index, output) in code.iter_mut().enumerate() {
        let shift = 25 - index * 5;
        *output = CROCKFORD[((value >> shift) & 0x1f) as usize];
    }
    format!(
        "{}-{}",
        std::str::from_utf8(&code[..3]).expect("ASCII"),
        std::str::from_utf8(&code[3..]).expect("ASCII")
    )
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0_u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK];
    let mut outer_pad = [0x5c_u8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad.as_slice());
    inner.update(message);
    let mut inner_hash: [u8; 32] = inner.finalize().into();
    let mut outer = Sha256::new();
    outer.update(outer_pad.as_slice());
    outer.update(inner_hash);
    let digest = outer.finalize().into();
    normalized.zeroize();
    inner_pad.zeroize();
    outer_pad.zeroize();
    inner_hash.zeroize();
    digest
}

fn enrollment_fingerprint(
    request: &RequestV2,
    host_endpoint_id: &str,
    client_endpoint_id: &str,
) -> Result<[u8; 32], RedeemError> {
    let mut encoded = Vec::with_capacity(512);
    encoded.extend_from_slice(ENROLLMENT_REQUEST_FINGERPRINT_DOMAIN);
    append_field(&mut encoded, host_endpoint_id.as_bytes())
        .map_err(|_| RedeemError::Unavailable)?;
    append_field(&mut encoded, client_endpoint_id.as_bytes())
        .map_err(|_| RedeemError::Unavailable)?;
    append_field(&mut encoded, &request.operation_payload_hash())
        .map_err(|_| RedeemError::Unavailable)?;
    Ok(Sha256::digest(encoded).into())
}

fn hash_operation_payload(fields: &[&str]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(256);
    encoded.extend_from_slice(OPERATION_PAYLOAD_DOMAIN);
    for field in fields {
        let _ = append_field(&mut encoded, field.as_bytes());
    }
    let digest = Sha256::digest(&encoded).into();
    encoded.zeroize();
    digest
}

fn append_field(target: &mut Vec<u8>, field: &[u8]) -> anyhow::Result<()> {
    let length = u32::try_from(field.len()).context("transcript field too large")?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(field);
    Ok(())
}

fn normalize_device_name(value: &str) -> String {
    let normalized: String = value
        .trim()
        .chars()
        .filter(|v| !v.is_control())
        .take(MAX_DEVICE_NAME_BYTES)
        .collect();
    if normalized.is_empty() {
        "Remora device".to_string()
    } else {
        normalized
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX)
}

async fn atomic_write(target: &Path, contents: &[u8]) -> anyhow::Result<CommitDurability> {
    let parent = target
        .parent()
        .ok_or_else(|| anyhow!("pairing store has no parent: {}", target.display()))?;
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("creating {}", parent.display()))?;
    let parent_directory = open_parent_directory(parent).await?;
    let mut suffix = [0_u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let temporary = target.with_extension(format!("tmp-{}", hex::encode(suffix)));
    let precommit_result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .await
            .with_context(|| format!("opening {}", temporary.display()))?;
        set_mode_0600(&temporary)?;
        file.write_all(contents)
            .await
            .with_context(|| format!("writing {}", temporary.display()))?;
        file.flush().await?;
        file.sync_all().await?;
        tokio::fs::rename(&temporary, target)
            .await
            .with_context(|| format!("renaming {} -> {}", temporary.display(), target.display()))?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if precommit_result.is_err()
        && let Err(cleanup_error) = tokio::fs::remove_file(&temporary).await
        && cleanup_error.kind() != std::io::ErrorKind::NotFound
    {
        warn!(path = %temporary.display(), "failed to remove pairing-store temporary file");
    }
    precommit_result?;
    Ok(
        match sync_parent_directory(&parent_directory, parent).await {
            Ok(()) => CommitDurability::Durable,
            Err(error) => CommitDurability::CommittedUnknown(error),
        },
    )
}

#[cfg(unix)]
async fn open_parent_directory(parent: &Path) -> anyhow::Result<tokio::fs::File> {
    tokio::fs::File::open(parent)
        .await
        .with_context(|| format!("opening pairing-store directory {}", parent.display()))
}
#[cfg(not(unix))]
async fn open_parent_directory(_parent: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
async fn sync_parent_directory(directory: &tokio::fs::File, parent: &Path) -> anyhow::Result<()> {
    #[cfg(test)]
    if tokio::fs::try_exists(parent.join(".force-remora-link-dir-sync-failure"))
        .await
        .unwrap_or(false)
    {
        return Err(anyhow!("injected pairing-store directory sync failure"));
    }
    directory
        .sync_all()
        .await
        .with_context(|| format!("syncing pairing-store directory {}", parent.display()))
}
#[cfg(not(unix))]
async fn sync_parent_directory(_directory: &(), _parent: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_mode_0600(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))
}
#[cfg(not(unix))]
fn set_mode_0600(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;

    async fn manager() -> (tempfile::TempDir, PairingManager) {
        let temp = tempfile::tempdir().unwrap();
        let manager = PairingManager::load(temp.path().join("pairing-v3.json"))
            .await
            .unwrap();
        (temp, manager)
    }

    fn policy() -> InvitationOptions {
        InvitationOptions {
            max_runtime_ids: vec!["claude".to_string(), "codex".to_string()],
            max_scopes: vec![
                DeviceScopeV2::InspectRuntimes,
                DeviceScopeV2::ConnectRuntime,
                DeviceScopeV2::RestartRuntime,
                DeviceScopeV2::SelfRevoke,
            ],
            confirmation_mode: ConfirmationModeV2::Interactive,
            ttl: DEFAULT_INVITATION_TTL,
        }
    }

    async fn invitation(
        manager: &PairingManager,
        options: InvitationOptions,
        now: i64,
    ) -> (String, PairingInvitation) {
        let host_id = iroh::SecretKey::generate().public().to_string();
        let invite = manager
            .create_invitation_at(
                host_id.clone(),
                Some("Development Mac".to_string()),
                None,
                options,
                now,
            )
            .await
            .unwrap();
        (host_id, invite)
    }

    fn signing_key_and_public() -> (SigningKey, String) {
        let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
        let public = signing_key.verifying_key().to_encoded_point(false);
        (signing_key, URL_SAFE_NO_PAD.encode(public.as_bytes()))
    }

    fn enroll_request(
        invite: &PairingInvitation,
        public_key: String,
        nonce: String,
        idempotency_key: &str,
        device_name: &str,
    ) -> RequestV2 {
        RequestV2::Enroll {
            v: PROTOCOL_VERSION_V2,
            invitation_id: invite.invitation_id.clone(),
            secret: invite.secret.clone(),
            device_name: device_name.to_string(),
            device_public_key: public_key,
            selected_runtime_ids: vec!["codex".to_string()],
            requested_scopes: vec![
                DeviceScopeV2::InspectRuntimes,
                DeviceScopeV2::ConnectRuntime,
                DeviceScopeV2::RestartRuntime,
                DeviceScopeV2::SelfRevoke,
            ],
            idempotency_key: idempotency_key.to_string(),
            client_nonce: nonce,
        }
    }

    fn sign_request(
        request: &RequestV2,
        challenge: &ProofChallengeV2,
        key: &SigningKey,
        host_id: &str,
        client_id: &str,
    ) -> ProofV2 {
        let public = key.verifying_key().to_encoded_point(false);
        let key_hash = Sha256::digest(public.as_bytes()).into();
        let transcript = encode_proof_transcript(&ProofTranscript {
            host_endpoint_id: host_id,
            client_endpoint_id: client_id,
            operation: request.operation(),
            credential_id: &challenge.credential_id,
            auth_epoch: challenge.auth_epoch,
            device_key_hash: &key_hash,
            challenge_id: &challenge.challenge_id,
            server_nonce: &challenge.server_nonce,
            client_nonce: request.client_nonce(),
            operation_payload_hash: &request.operation_payload_hash(),
        })
        .unwrap();
        let signature: Signature = key.sign(&transcript);
        ProofV2 {
            v: PROTOCOL_VERSION_V2,
            challenge_id: challenge.challenge_id.clone(),
            signature: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
        }
    }

    // Keeping the full transcript inputs explicit makes each security test's
    // endpoint, key, operation id, and clock visible at the call site.
    #[allow(clippy::too_many_arguments)]
    async fn submit_enrollment(
        manager: &PairingManager,
        invite: &PairingInvitation,
        host_id: &str,
        endpoint: &str,
        key: &SigningKey,
        public: String,
        idempotency_key: &str,
        name: &str,
        now: i64,
    ) -> (RequestV2, EnrollmentOutcomeV2) {
        let request = enroll_request(
            invite,
            public,
            random_urlsafe(NONCE_BYTES),
            idempotency_key,
            name,
        );
        let challenge = ProofChallengeV2::issue_at(random_urlsafe(DEVICE_ID_BYTES), 0, now);
        let proof = sign_request(&request, &challenge, key, host_id, endpoint);
        let result = manager
            .enroll_at(&request, &challenge, &proof, host_id, endpoint, now)
            .await
            .unwrap();
        (request, result)
    }

    async fn approve_test_device(
        manager: &PairingManager,
        now: i64,
    ) -> (String, SigningKey, EnrolledDevice) {
        let (host_id, invite) = invitation(manager, policy(), now).await;
        let (key, public) = signing_key_and_public();
        let (_, outcome) = submit_enrollment(
            manager,
            &invite,
            &host_id,
            "phone",
            &key,
            public,
            "enroll-operation-1",
            "Phone",
            now + 1,
        )
        .await;
        let EnrollmentOutcomeV2::Pending { pending } = outcome else {
            panic!("expected pending")
        };
        let enrolled = manager
            .approve_pending(
                &pending.claim_id,
                &["codex".to_string()],
                &[
                    DeviceScopeV2::InspectRuntimes,
                    DeviceScopeV2::ConnectRuntime,
                    DeviceScopeV2::RestartRuntime,
                    DeviceScopeV2::SelfRevoke,
                ],
            )
            .await
            .unwrap()
            .unwrap();
        (host_id, key, enrolled)
    }

    async fn authorize_restart_request(
        manager: &PairingManager,
        host_id: &str,
        key: &SigningKey,
        enrolled: &EnrolledDevice,
        idempotency_key: &str,
        command_sequence: u64,
        now: i64,
    ) -> (RequestV2, AuthorizationContextV2) {
        let request = RequestV2::RestartAgent {
            v: PROTOCOL_VERSION_V2,
            credential_id: enrolled.device_id.clone(),
            client_nonce: random_urlsafe(NONCE_BYTES),
            agent: "codex".to_string(),
            idempotency_key: idempotency_key.to_string(),
            command_sequence,
        };
        let challenge =
            ProofChallengeV2::issue_at(enrolled.device_id.clone(), enrolled.auth_epoch, now);
        let proof = sign_request(&request, &challenge, key, host_id, "phone");
        let authorization = manager
            .authorize_operation_at(&request, &challenge, &proof, host_id, "phone", now)
            .await
            .unwrap();
        (request, authorization)
    }

    #[test]
    fn unattended_policy_is_conspicuously_narrow_and_bounded() {
        assert!(
            validate_policy(
                &["codex".to_string()],
                &[
                    DeviceScopeV2::InspectRuntimes,
                    DeviceScopeV2::ConnectRuntime,
                    DeviceScopeV2::SelfRevoke
                ],
                ConfirmationModeV2::Unattended,
                MAX_UNATTENDED_INVITATION_TTL
            )
            .is_ok()
        );
        assert!(
            validate_policy(
                &["claude".to_string(), "codex".to_string()],
                &[
                    DeviceScopeV2::InspectRuntimes,
                    DeviceScopeV2::ConnectRuntime,
                    DeviceScopeV2::SelfRevoke
                ],
                ConfirmationModeV2::Unattended,
                MAX_UNATTENDED_INVITATION_TTL
            )
            .is_err()
        );
        assert!(
            validate_policy(
                &["codex".to_string()],
                &[
                    DeviceScopeV2::InspectRuntimes,
                    DeviceScopeV2::ConnectRuntime,
                    DeviceScopeV2::RestartRuntime,
                    DeviceScopeV2::SelfRevoke
                ],
                ConfirmationModeV2::Unattended,
                Duration::from_secs(61)
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn unattended_enrollment_requires_the_exact_narrow_default_grant() {
        let (_temp, manager) = manager().await;
        let now = unix_now();
        let (host_id, invite) = invitation(
            &manager,
            InvitationOptions::unattended("codex".to_string()),
            now,
        )
        .await;
        let (key, public) = signing_key_and_public();
        let build_request = |scopes: Vec<DeviceScopeV2>, operation: &str| RequestV2::Enroll {
            v: PROTOCOL_VERSION_V2,
            invitation_id: invite.invitation_id.clone(),
            secret: invite.secret.clone(),
            device_name: "Phone".to_string(),
            device_public_key: public.clone(),
            selected_runtime_ids: vec!["codex".to_string()],
            requested_scopes: scopes,
            idempotency_key: operation.to_string(),
            client_nonce: random_urlsafe(NONCE_BYTES),
        };
        let narrowed = build_request(
            vec![DeviceScopeV2::ConnectRuntime, DeviceScopeV2::SelfRevoke],
            "unattended-narrowed",
        );
        let challenge = manager.issue_challenge(&narrowed, "phone").await.unwrap();
        let proof = sign_request(&narrowed, &challenge, &key, &host_id, "phone");
        assert_eq!(
            manager
                .enroll_at(&narrowed, &challenge, &proof, &host_id, "phone", now + 1,)
                .await,
            Err(RedeemError::Unavailable)
        );

        let exact = build_request(
            vec![
                DeviceScopeV2::InspectRuntimes,
                DeviceScopeV2::ConnectRuntime,
                DeviceScopeV2::SelfRevoke,
            ],
            "unattended-exact",
        );
        let challenge = manager.issue_challenge(&exact, "phone").await.unwrap();
        let proof = sign_request(&exact, &challenge, &key, &host_id, "phone");
        assert!(matches!(
            manager
                .enroll_at(&exact, &challenge, &proof, &host_id, "phone", now + 2,)
                .await
                .unwrap(),
            EnrollmentOutcomeV2::Enrolled { .. }
        ));
    }

    #[tokio::test]
    async fn prospective_credentials_are_stable_without_an_invitation_existence_oracle() {
        let (_temp, manager) = manager().await;
        let now = unix_now();
        let (_host_id, invite) = invitation(&manager, policy(), now).await;
        let (_key, public) = signing_key_and_public();
        let request = enroll_request(
            &invite,
            public.clone(),
            random_urlsafe(NONCE_BYTES),
            "enroll-operation-1",
            "Phone",
        );
        let first = manager.issue_challenge(&request, "phone").await.unwrap();
        let repeated = manager.issue_challenge(&request, "phone").await.unwrap();
        assert_eq!(first.credential_id, repeated.credential_id);
        assert_eq!(first.credential_id.len(), 22);

        let wrong_key = enroll_request(
            &invite,
            public.clone(),
            random_urlsafe(NONCE_BYTES),
            "wrong-enrollment-operation",
            "Phone",
        );
        let wrong_first = manager.issue_challenge(&wrong_key, "phone").await.unwrap();
        let wrong_repeated = manager.issue_challenge(&wrong_key, "phone").await.unwrap();
        assert_eq!(wrong_first.credential_id, wrong_repeated.credential_id);
        assert_ne!(first.credential_id, wrong_first.credential_id);

        let mut unknown_invitation = invite.clone();
        unknown_invitation.invitation_id = random_urlsafe(INVITATION_ID_BYTES);
        let unknown = enroll_request(
            &unknown_invitation,
            public,
            random_urlsafe(NONCE_BYTES),
            "enroll-operation-1",
            "Phone",
        );
        assert!(manager.issue_challenge(&unknown, "phone").await.is_ok());
    }

    #[tokio::test]
    async fn pairing_code_decode_is_clock_independent_but_host_expiry_is_authoritative() {
        let (_temp, manager) = manager().await;
        let (host_id, invite) = invitation(&manager, policy(), 0).await;
        let code = invite.to_pairing_code().unwrap();
        let decoded = PairingInvitation::from_pairing_code(&code).unwrap();
        assert_eq!(decoded.invitation_id, invite.invitation_id);
        assert_eq!(decoded.expires_at, DEFAULT_INVITATION_TTL.as_secs() as i64);

        let (key, public) = signing_key_and_public();
        let request = RequestV2::InspectInvitation {
            v: PROTOCOL_VERSION_V2,
            invitation_id: invite.invitation_id.clone(),
            secret: invite.secret.clone(),
            device_public_key: public,
            client_nonce: random_urlsafe(NONCE_BYTES),
        };
        let expired_at = DEFAULT_INVITATION_TTL.as_secs() as i64 + 1;
        let challenge = ProofChallengeV2::issue_at(invite.invitation_id.clone(), 0, expired_at);
        let proof = sign_request(&request, &challenge, &key, &host_id, "phone");
        assert_eq!(
            manager
                .inspect_at(&request, &challenge, &proof, &host_id, "phone", expired_at,)
                .await,
            Err(RedeemError::Unavailable)
        );
    }

    #[tokio::test]
    async fn secret_zeroization_and_raw_device_name_bounds_are_explicit() {
        let (_temp, manager) = manager().await;
        let now = unix_now();
        let (_host_id, mut invite) = invitation(&manager, policy(), now).await;
        let (_key, public) = signing_key_and_public();
        let mut request = enroll_request(
            &invite,
            public,
            random_urlsafe(NONCE_BYTES),
            "enroll-operation-1",
            "Phone",
        );

        if let RequestV2::Enroll { device_name, .. } = &mut request {
            *device_name = " ".repeat(MAX_DEVICE_NAME_BYTES);
        }
        assert!(validate_request(&request).is_ok());
        assert_eq!(
            normalize_device_name(&" ".repeat(MAX_DEVICE_NAME_BYTES)),
            "Remora device"
        );
        if let RequestV2::Enroll { device_name, .. } = &mut request {
            *device_name = " ".repeat(MAX_DEVICE_NAME_BYTES + 1);
        }
        assert_eq!(validate_request(&request), Err(RedeemError::Unavailable));
        if let RequestV2::Enroll { device_name, .. } = &mut request {
            *device_name = "Phone\n".to_string();
        }
        assert_eq!(validate_request(&request), Err(RedeemError::Unavailable));

        request.zeroize_invitation_secret();
        assert!(matches!(
            &request,
            RequestV2::Enroll { secret, .. } if secret.is_empty()
        ));
        invite.zeroize_secret();
        assert!(invite.secret.is_empty());
    }

    #[tokio::test]
    async fn oversized_pairing_envelope_is_rejected_before_persistence() {
        let (_temp, manager) = manager().await;
        let host_id = iroh::SecretKey::generate().public().to_string();
        let relay = format!("https://relay.example/{}", "a".repeat(6_000));
        let invitation = PairingInvitation {
            v: PROTOCOL_VERSION_V2,
            node_id: host_id.clone(),
            invitation_id: random_urlsafe(INVITATION_ID_BYTES),
            secret: random_urlsafe(INVITATION_SECRET_BYTES),
            expires_at: unix_now() + DEFAULT_INVITATION_TTL.as_secs() as i64,
            max_runtime_ids: policy().max_runtime_ids,
            max_scopes: policy().max_scopes,
            confirmation_mode: ConfirmationModeV2::Interactive,
            host_name: None,
            relay: Some(relay.clone()),
        };
        assert!(invitation.to_pairing_code().is_err());
        assert!(
            manager
                .create_invitation(host_id, None, Some(relay), policy(),)
                .await
                .is_err()
        );
        assert!(manager.state.lock().await.invitations.is_empty());
    }

    #[tokio::test]
    async fn inspection_is_authenticated_and_does_not_consume_invitation() {
        let (_temp, manager) = manager().await;
        let now = unix_now();
        let (host_id, invite) = invitation(&manager, policy(), now).await;
        let (key, public) = signing_key_and_public();
        let request = RequestV2::InspectInvitation {
            v: PROTOCOL_VERSION_V2,
            invitation_id: invite.invitation_id.clone(),
            secret: invite.secret.clone(),
            device_public_key: public,
            client_nonce: random_urlsafe(NONCE_BYTES),
        };
        let challenge = ProofChallengeV2::issue_at(invite.invitation_id.clone(), 0, now);
        let proof = sign_request(&request, &challenge, &key, &host_id, "phone-endpoint");
        let inspected = manager
            .inspect_at(
                &request,
                &challenge,
                &proof,
                &host_id,
                "phone-endpoint",
                now,
            )
            .await
            .unwrap();
        assert_eq!(inspected.max_runtime_ids, vec!["claude", "codex"]);
        assert!(
            manager.state.lock().await.invitations[&invite.invitation_id]
                .claim
                .is_none()
        );

        let (_request, outcome) = submit_enrollment(
            &manager,
            &invite,
            &host_id,
            "phone-endpoint",
            &key,
            URL_SAFE_NO_PAD.encode(key.verifying_key().to_encoded_point(false).as_bytes()),
            "enroll-operation-1",
            "Aman's phone",
            now + 1,
        )
        .await;
        assert!(matches!(outcome, EnrollmentOutcomeV2::Pending { .. }));
    }

    #[tokio::test]
    async fn issued_and_pending_invitations_share_one_hard_capacity_bound() {
        let (_temp, manager) = manager().await;
        let now = unix_now();
        let (first_host, first_invite) = invitation(&manager, policy(), now).await;
        let (key, public) = signing_key_and_public();
        let (_, outcome) = submit_enrollment(
            &manager,
            &first_invite,
            &first_host,
            "phone",
            &key,
            public,
            "enroll-operation-1",
            "Phone",
            now + 1,
        )
        .await;
        assert!(matches!(outcome, EnrollmentOutcomeV2::Pending { .. }));
        for _ in 1..MAX_OPEN_INVITATIONS {
            invitation(&manager, policy(), now).await;
        }
        let host_id = iroh::SecretKey::generate().public().to_string();
        assert!(
            manager
                .create_invitation_at(host_id, None, None, policy(), now)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn first_claim_is_reserved_and_exact_replay_is_idempotent() {
        let (_temp, manager) = manager().await;
        let now = unix_now();
        let (host_id, invite) = invitation(&manager, policy(), now).await;
        let (key, public) = signing_key_and_public();
        let (_first_request, first) = submit_enrollment(
            &manager,
            &invite,
            &host_id,
            "phone-a",
            &key,
            public.clone(),
            "enroll-operation-1",
            "Phone",
            now + 1,
        )
        .await;
        let EnrollmentOutcomeV2::Pending { pending } = first else {
            panic!("expected pending")
        };

        let replay = enroll_request(
            &invite,
            public.clone(),
            random_urlsafe(NONCE_BYTES),
            "enroll-operation-1",
            "Phone",
        );
        let replay_challenge =
            ProofChallengeV2::issue_at(pending.credential_id.clone(), 0, now + 2);
        let replay_proof = sign_request(&replay, &replay_challenge, &key, &host_id, "phone-a");
        let replayed = manager
            .enroll_at(
                &replay,
                &replay_challenge,
                &replay_proof,
                &host_id,
                "phone-a",
                now + 2,
            )
            .await
            .unwrap();
        assert_eq!(
            replayed,
            EnrollmentOutcomeV2::Pending {
                pending: pending.clone()
            }
        );

        let changed = enroll_request(
            &invite,
            public,
            random_urlsafe(NONCE_BYTES),
            "enroll-operation-1",
            "Changed phone",
        );
        let changed_challenge = ProofChallengeV2::issue_at(pending.credential_id, 0, now + 3);
        let changed_proof = sign_request(&changed, &changed_challenge, &key, &host_id, "phone-a");
        assert_eq!(
            manager
                .enroll_at(
                    &changed,
                    &changed_challenge,
                    &changed_proof,
                    &host_id,
                    "phone-a",
                    now + 3
                )
                .await,
            Err(RedeemError::Unavailable)
        );
    }

    #[tokio::test]
    async fn concurrent_claims_produce_only_one_pending_grant() {
        let (_temp, manager) = manager().await;
        let now = unix_now();
        let (host_id, invite) = invitation(&manager, policy(), now).await;
        let (left_key, left_public) = signing_key_and_public();
        let (right_key, right_public) = signing_key_and_public();
        let left_request = enroll_request(
            &invite,
            left_public,
            random_urlsafe(NONCE_BYTES),
            "left-operation",
            "Left",
        );
        let right_request = enroll_request(
            &invite,
            right_public,
            random_urlsafe(NONCE_BYTES),
            "right-operation",
            "Right",
        );
        let left_challenge =
            ProofChallengeV2::issue_at(random_urlsafe(DEVICE_ID_BYTES), 0, now + 1);
        let right_challenge =
            ProofChallengeV2::issue_at(random_urlsafe(DEVICE_ID_BYTES), 0, now + 1);
        let left_proof = sign_request(
            &left_request,
            &left_challenge,
            &left_key,
            &host_id,
            "left-endpoint",
        );
        let right_proof = sign_request(
            &right_request,
            &right_challenge,
            &right_key,
            &host_id,
            "right-endpoint",
        );
        let (left, right) = tokio::join!(
            manager.enroll_at(
                &left_request,
                &left_challenge,
                &left_proof,
                &host_id,
                "left-endpoint",
                now + 1
            ),
            manager.enroll_at(
                &right_request,
                &right_challenge,
                &right_proof,
                &host_id,
                "right-endpoint",
                now + 1
            )
        );
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        assert_eq!(manager.list_pending().await.len(), 1);
        assert!(manager.list_devices().await.is_empty());
    }

    #[tokio::test]
    async fn host_approval_can_only_narrow_and_operation_checks_fail_closed() {
        let (_temp, manager) = manager().await;
        let now = unix_now();
        let (host_id, invite) = invitation(&manager, policy(), now).await;
        let (key, public) = signing_key_and_public();
        let (_request, outcome) = submit_enrollment(
            &manager,
            &invite,
            &host_id,
            "phone",
            &key,
            public,
            "enroll-operation-1",
            "Phone",
            now + 1,
        )
        .await;
        let EnrollmentOutcomeV2::Pending { pending } = outcome else {
            panic!("expected pending")
        };
        assert!(
            manager
                .approve_pending(
                    &pending.claim_id,
                    &["unknown".to_string()],
                    &[DeviceScopeV2::ConnectRuntime, DeviceScopeV2::SelfRevoke]
                )
                .await
                .is_err()
        );
        let scopes = vec![
            DeviceScopeV2::InspectRuntimes,
            DeviceScopeV2::ConnectRuntime,
            DeviceScopeV2::SelfRevoke,
        ];
        let enrolled = manager
            .approve_pending(&pending.claim_id, &["codex".to_string()], &scopes)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(enrolled.granted_scopes, scopes);

        let status_request = RequestV2::CommandCenterStatus {
            v: PROTOCOL_VERSION_V2,
            credential_id: enrolled.device_id.clone(),
            client_nonce: random_urlsafe(NONCE_BYTES),
        };
        let status_challenge = ProofChallengeV2::issue_at(enrolled.device_id.clone(), 0, now + 2);
        let status_proof =
            sign_request(&status_request, &status_challenge, &key, &host_id, "phone");
        manager
            .authorize_operation_at(
                &status_request,
                &status_challenge,
                &status_proof,
                &host_id,
                "phone",
                now + 2,
            )
            .await
            .unwrap();
        let mut no_inspection_grant =
            manager.state.lock().await.devices[&enrolled.device_id].clone();
        no_inspection_grant
            .granted_scopes
            .retain(|scope| *scope != DeviceScopeV2::InspectRuntimes);
        assert_eq!(
            enforce_operation_grant(&status_request, &no_inspection_grant),
            Err(RedeemError::Unavailable)
        );

        let allowed = RequestV2::Connect {
            v: PROTOCOL_VERSION_V2,
            credential_id: enrolled.device_id.clone(),
            client_nonce: random_urlsafe(NONCE_BYTES),
            agent: "codex".to_string(),
            resume: None,
        };
        let challenge = ProofChallengeV2::issue_at(enrolled.device_id.clone(), 0, now + 3);
        let proof = sign_request(&allowed, &challenge, &key, &host_id, "phone");
        let context = manager
            .authorize_operation_at(&allowed, &challenge, &proof, &host_id, "phone", now + 3)
            .await
            .unwrap();
        assert!(manager.is_authorization_current(&context, "phone").await);

        let denied = RequestV2::RestartAgent {
            v: PROTOCOL_VERSION_V2,
            credential_id: enrolled.device_id.clone(),
            client_nonce: random_urlsafe(NONCE_BYTES),
            agent: "codex".to_string(),
            idempotency_key: "restart-operation-1".to_string(),
            command_sequence: 1,
        };
        let denied_challenge = ProofChallengeV2::issue_at(enrolled.device_id, 0, now + 4);
        let denied_proof = sign_request(&denied, &denied_challenge, &key, &host_id, "phone");
        assert_eq!(
            manager
                .authorize_operation_at(
                    &denied,
                    &denied_challenge,
                    &denied_proof,
                    &host_id,
                    "phone",
                    now + 4
                )
                .await,
            Err(RedeemError::Unavailable)
        );
    }

    #[tokio::test]
    async fn connect_start_permit_linearizes_against_revocation() {
        let (_temp, manager) = manager().await;
        let now = unix_now();
        let (_, _, enrolled) = approve_test_device(&manager, now).await;
        let authorization = manager.state.lock().await.devices[&enrolled.device_id].authorization();
        let permit = manager
            .prepare_connect_start(&authorization, "phone")
            .await
            .unwrap();
        let setup = tokio::spawn(crate::host::run_bounded_connect_setup(
            permit,
            Duration::from_millis(50),
            std::future::pending::<()>(),
        ));

        let revoke_manager = manager.clone();
        let credential_id = enrolled.device_id.clone();
        let mut revoke =
            tokio::spawn(async move { revoke_manager.revoke_device(&credential_id).await });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut revoke)
                .await
                .is_err(),
            "revocation committed while connect-start read fence was held"
        );
        assert_eq!(manager.list_devices().await[0].state, GrantStateV2::Active);

        assert!(setup.await.unwrap().is_err());
        let revoked = tokio::time::timeout(Duration::from_secs(2), revoke)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(revoked.state, GrantStateV2::Revoked);
        assert_eq!(
            manager
                .prepare_connect_start(&authorization, "phone")
                .await
                .map(|_| ()),
            Err(RedeemError::Unavailable)
        );
    }

    #[tokio::test]
    async fn restart_journal_sequences_replay_prune_and_fence_revocation() {
        let (temp, manager) = manager().await;
        let now = unix_now();
        let (host_id, key, enrolled) = approve_test_device(&manager, now).await;

        let zero = RequestV2::RestartAgent {
            v: PROTOCOL_VERSION_V2,
            credential_id: enrolled.device_id.clone(),
            client_nonce: random_urlsafe(NONCE_BYTES),
            agent: "codex".to_string(),
            idempotency_key: "restart-zero".to_string(),
            command_sequence: 0,
        };
        assert_eq!(validate_request(&zero), Err(RedeemError::Unavailable));

        let (gap, gap_authorization) = authorize_restart_request(
            &manager,
            &host_id,
            &key,
            &enrolled,
            "restart-gap",
            2,
            now + 2,
        )
        .await;
        assert!(matches!(
            manager
                .prepare_restart(&gap, &gap_authorization, "phone", true)
                .await,
            Err(RedeemError::Unavailable)
        ));

        let (disabled, disabled_authorization) = authorize_restart_request(
            &manager,
            &host_id,
            &key,
            &enrolled,
            "restart-one",
            1,
            now + 3,
        )
        .await;
        assert!(matches!(
            manager
                .prepare_restart(&disabled, &disabled_authorization, "phone", false)
                .await,
            Err(RedeemError::AgentUnavailable)
        ));

        let (first, first_authorization) = authorize_restart_request(
            &manager,
            &host_id,
            &key,
            &enrolled,
            "restart-one",
            1,
            now + 4,
        )
        .await;
        let first_dispatch = match manager
            .prepare_restart(&first, &first_authorization, "phone", true)
            .await
            .unwrap()
        {
            RestartPreparationV2::Execute(dispatch) => dispatch,
            other => panic!("expected first restart dispatch, got {other:?}"),
        };
        assert_eq!(
            manager.state.lock().await.restart_high_watermarks[&enrolled.device_id],
            1
        );
        drop(first_dispatch);

        let (first_replay, first_replay_authorization) = authorize_restart_request(
            &manager,
            &host_id,
            &key,
            &enrolled,
            "restart-one",
            1,
            now + 5,
        )
        .await;
        assert!(matches!(
            manager
                .prepare_restart(&first_replay, &first_replay_authorization, "phone", false,)
                .await
                .unwrap(),
            RestartPreparationV2::OutcomeUnknown(RestartResultV2 {
                command_sequence: 1,
                ..
            })
        ));

        let (conflict, conflict_authorization) = authorize_restart_request(
            &manager,
            &host_id,
            &key,
            &enrolled,
            "different-key",
            1,
            now + 6,
        )
        .await;
        assert!(matches!(
            manager
                .prepare_restart(&conflict, &conflict_authorization, "phone", true)
                .await,
            Err(RedeemError::Unavailable)
        ));

        let (second, second_authorization) = authorize_restart_request(
            &manager,
            &host_id,
            &key,
            &enrolled,
            "restart-two",
            2,
            now + 7,
        )
        .await;
        let second_dispatch = match manager
            .prepare_restart(&second, &second_authorization, "phone", true)
            .await
            .unwrap()
        {
            RestartPreparationV2::Execute(dispatch) => dispatch,
            other => panic!("expected second restart dispatch, got {other:?}"),
        };
        let succeeded = manager
            .mark_restart_succeeded(&second_dispatch)
            .await
            .unwrap();
        assert_eq!(succeeded.status, RestartStatusV2::Succeeded);
        assert_eq!(succeeded.command_sequence, 2);
        drop(second_dispatch);
        drop(manager);
        let manager = PairingManager::load(temp.path().join("pairing-v3.json"))
            .await
            .unwrap();

        let (prepared_after_reload, prepared_after_reload_authorization) =
            authorize_restart_request(
                &manager,
                &host_id,
                &key,
                &enrolled,
                "restart-one",
                1,
                now + 8,
            )
            .await;
        assert!(matches!(
            manager
                .prepare_restart(
                    &prepared_after_reload,
                    &prepared_after_reload_authorization,
                    "phone",
                    false,
                )
                .await
                .unwrap(),
            RestartPreparationV2::OutcomeUnknown(RestartResultV2 {
                command_sequence: 1,
                ..
            })
        ));

        let (second_replay, second_replay_authorization) = authorize_restart_request(
            &manager,
            &host_id,
            &key,
            &enrolled,
            "restart-two",
            2,
            now + 9,
        )
        .await;
        assert!(matches!(
            manager
                .prepare_restart(&second_replay, &second_replay_authorization, "phone", false,)
                .await
                .unwrap(),
            RestartPreparationV2::Succeeded(RestartResultV2 {
                command_sequence: 2,
                ..
            })
        ));

        let (reused_key, reused_key_authorization) = authorize_restart_request(
            &manager,
            &host_id,
            &key,
            &enrolled,
            "restart-two",
            3,
            now + 10,
        )
        .await;
        assert!(matches!(
            manager
                .prepare_restart(&reused_key, &reused_key_authorization, "phone", true)
                .await,
            Err(RedeemError::Unavailable)
        ));

        {
            let mut state = manager.state.lock().await;
            for sequence in 3..=MAX_RESTART_COMMANDS_PER_DEVICE as u64 {
                state.restart_commands.insert(
                    restart_journal_key(&enrolled.device_id, sequence),
                    RestartCommandRecord {
                        command_id: format!("synthetic-command-{sequence}"),
                        credential_id: enrolled.device_id.clone(),
                        idempotency_key: format!("synthetic-key-{sequence}"),
                        command_sequence: sequence,
                        request_fingerprint: format!("synthetic-fingerprint-{sequence}"),
                        agent: "codex".to_string(),
                        auth_epoch: enrolled.auth_epoch,
                        status: RestartCommandStatus::Succeeded,
                        created_at: now,
                        succeeded_at: Some(now),
                    },
                );
            }
            state.restart_high_watermarks.insert(
                enrolled.device_id.clone(),
                MAX_RESTART_COMMANDS_PER_DEVICE as u64,
            );
        }
        let next_sequence = MAX_RESTART_COMMANDS_PER_DEVICE as u64 + 1;
        let (next, next_authorization) = authorize_restart_request(
            &manager,
            &host_id,
            &key,
            &enrolled,
            "restart-next",
            next_sequence,
            now + 11,
        )
        .await;
        let next_dispatch = match manager
            .prepare_restart(&next, &next_authorization, "phone", true)
            .await
            .unwrap()
        {
            RestartPreparationV2::Execute(dispatch) => dispatch,
            other => panic!("expected next restart dispatch, got {other:?}"),
        };
        {
            let state = manager.state.lock().await;
            assert_eq!(
                state
                    .restart_commands
                    .values()
                    .filter(|record| record.credential_id == enrolled.device_id)
                    .count(),
                MAX_RESTART_COMMANDS_PER_DEVICE
            );
            assert!(
                !state
                    .restart_commands
                    .contains_key(&restart_journal_key(&enrolled.device_id, 1))
            );
        }
        let (pruned_replay, pruned_authorization) = authorize_restart_request(
            &manager,
            &host_id,
            &key,
            &enrolled,
            "restart-one",
            1,
            now + 12,
        )
        .await;
        assert!(matches!(
            manager
                .prepare_restart(&pruned_replay, &pruned_authorization, "phone", false)
                .await
                .unwrap(),
            RestartPreparationV2::OutcomeUnknown(RestartResultV2 {
                command_sequence: 1,
                ..
            })
        ));

        let revoke_manager = manager.clone();
        let credential_id = enrolled.device_id.clone();
        let mut revoke =
            tokio::spawn(async move { revoke_manager.revoke_device(&credential_id).await });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut revoke)
                .await
                .is_err(),
            "revocation committed while restart dispatch fence was held"
        );
        drop(next_dispatch);
        let revoked = tokio::time::timeout(Duration::from_secs(2), revoke)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(revoked.state, GrantStateV2::Revoked);
    }

    #[tokio::test]
    async fn self_revoke_is_durable_idempotent_and_increments_epoch() {
        let (temp, manager) = manager().await;
        let now = unix_now();
        let (host_id, invite) = invitation(&manager, policy(), now).await;
        let (key, public) = signing_key_and_public();
        let (_request, outcome) = submit_enrollment(
            &manager,
            &invite,
            &host_id,
            "phone",
            &key,
            public,
            "enroll-operation-1",
            "Phone",
            now + 1,
        )
        .await;
        let EnrollmentOutcomeV2::Pending { pending } = outcome else {
            panic!("expected pending")
        };
        let scopes = vec![
            DeviceScopeV2::InspectRuntimes,
            DeviceScopeV2::ConnectRuntime,
            DeviceScopeV2::SelfRevoke,
        ];
        let enrolled = manager
            .approve_pending(&pending.claim_id, &["codex".to_string()], &scopes)
            .await
            .unwrap()
            .unwrap();
        let request = RequestV2::RevokeSelf {
            v: PROTOCOL_VERSION_V2,
            credential_id: enrolled.device_id.clone(),
            client_nonce: random_urlsafe(NONCE_BYTES),
            idempotency_key: "self-revoke-operation-1".to_string(),
        };
        let challenge = ProofChallengeV2::issue_at(enrolled.device_id.clone(), 0, now + 2);
        let proof = sign_request(&request, &challenge, &key, &host_id, "phone");
        let revocation = manager
            .revoke_mutation(
                &request,
                ProofExchange {
                    challenge: &challenge,
                    proof: &proof,
                    host_endpoint_id: &host_id,
                    client_endpoint_id: "phone",
                },
                now + 2,
                false,
            )
            .await
            .unwrap();
        let receipt = revocation.receipt().clone();
        assert_eq!(receipt.auth_epoch, 1);

        let replay = RequestV2::RevokeSelf {
            v: PROTOCOL_VERSION_V2,
            credential_id: enrolled.device_id.clone(),
            client_nonce: random_urlsafe(NONCE_BYTES),
            idempotency_key: "self-revoke-operation-1".to_string(),
        };
        let replay_challenge = ProofChallengeV2::issue_at(enrolled.device_id.clone(), 1, now + 3);
        let replay_proof = sign_request(&replay, &replay_challenge, &key, &host_id, "phone");
        assert_eq!(
            manager
                .revoke_mutation(
                    &replay,
                    ProofExchange {
                        challenge: &replay_challenge,
                        proof: &replay_proof,
                        host_endpoint_id: &host_id,
                        client_endpoint_id: "phone"
                    },
                    now + 3,
                    false
                )
                .await
                .unwrap(),
            RevocationMutationV2::Durable(receipt)
        );
        let different_operation = RequestV2::RevokeSelf {
            v: PROTOCOL_VERSION_V2,
            credential_id: enrolled.device_id.clone(),
            client_nonce: random_urlsafe(NONCE_BYTES),
            idempotency_key: "self-revoke-operation-2".to_string(),
        };
        let different_challenge =
            ProofChallengeV2::issue_at(enrolled.device_id.clone(), 1, now + 4);
        let different_proof = sign_request(
            &different_operation,
            &different_challenge,
            &key,
            &host_id,
            "phone",
        );
        assert_eq!(
            manager
                .revoke_mutation(
                    &different_operation,
                    ProofExchange {
                        challenge: &different_challenge,
                        proof: &different_proof,
                        host_endpoint_id: &host_id,
                        client_endpoint_id: "phone",
                    },
                    now + 4,
                    false,
                )
                .await,
            Err(RedeemError::Unavailable)
        );
        let reloaded = PairingManager::load(temp.path().join("pairing-v3.json"))
            .await
            .unwrap();
        assert_eq!(
            reloaded.list_devices().await[0].state,
            GrantStateV2::Revoked
        );
        assert_eq!(reloaded.list_devices().await[0].auth_epoch, 1);
    }

    #[tokio::test]
    async fn pending_enrollment_can_be_rolled_back_once_with_fresh_proof() {
        let (_temp, manager) = manager().await;
        let now = unix_now();
        let (host_id, invite) = invitation(&manager, policy(), now).await;
        let (key, public) = signing_key_and_public();
        let (_request, outcome) = submit_enrollment(
            &manager,
            &invite,
            &host_id,
            "phone",
            &key,
            public,
            "enroll-operation-1",
            "Phone",
            now + 1,
        )
        .await;
        let EnrollmentOutcomeV2::Pending { pending } = outcome else {
            panic!("expected pending")
        };
        let rollback = RequestV2::RollbackEnrollment {
            v: PROTOCOL_VERSION_V2,
            credential_id: pending.credential_id.clone(),
            enrollment_idempotency_key: "enroll-operation-1".to_string(),
            client_nonce: random_urlsafe(NONCE_BYTES),
            idempotency_key: "rollback-operation-1".to_string(),
        };
        let challenge = ProofChallengeV2::issue_at(pending.credential_id, 0, now + 2);
        let proof = sign_request(&rollback, &challenge, &key, &host_id, "phone");
        let revocation = manager
            .revoke_mutation(
                &rollback,
                ProofExchange {
                    challenge: &challenge,
                    proof: &proof,
                    host_endpoint_id: &host_id,
                    client_endpoint_id: "phone",
                },
                now + 2,
                true,
            )
            .await
            .unwrap();
        let receipt = revocation.receipt();
        assert_eq!(receipt.auth_epoch, 1);
        assert!(manager.list_pending().await.is_empty());
        assert!(manager.list_devices().await.is_empty());
    }

    #[tokio::test]
    async fn daemon_restart_preserves_pending_claim_exact_replay_and_approval() {
        let (temp, manager) = manager().await;
        let now = unix_now();
        let (host_id, invite) = invitation(&manager, policy(), now).await;
        let (key, public) = signing_key_and_public();
        let (_request, outcome) = submit_enrollment(
            &manager,
            &invite,
            &host_id,
            "phone",
            &key,
            public.clone(),
            "enroll-operation-1",
            "Phone",
            now + 1,
        )
        .await;
        let EnrollmentOutcomeV2::Pending { pending } = outcome else {
            panic!("expected pending")
        };
        drop(manager);

        let reloaded = PairingManager::load(temp.path().join("pairing-v3.json"))
            .await
            .unwrap();
        assert_eq!(reloaded.list_pending().await.len(), 1);
        let replay = enroll_request(
            &invite,
            public.clone(),
            random_urlsafe(NONCE_BYTES),
            "enroll-operation-1",
            "Phone",
        );
        let challenge = ProofChallengeV2::issue_at(pending.credential_id.clone(), 0, now + 2);
        let proof = sign_request(&replay, &challenge, &key, &host_id, "phone");
        assert_eq!(
            reloaded
                .enroll_at(&replay, &challenge, &proof, &host_id, "phone", now + 2,)
                .await
                .unwrap(),
            EnrollmentOutcomeV2::Pending {
                pending: pending.clone()
            }
        );
        let enrolled = reloaded
            .approve_pending(
                &pending.claim_id,
                &["codex".to_string()],
                &[
                    DeviceScopeV2::InspectRuntimes,
                    DeviceScopeV2::ConnectRuntime,
                    DeviceScopeV2::SelfRevoke,
                ],
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(enrolled.device_id, pending.credential_id);
        assert_eq!(
            enrolled.enrollment_confirmation,
            pending.enrollment_confirmation
        );

        // A client that lost the Pending response may repeat the same logical
        // enrollment with a fresh proof after host approval. It must recover
        // the byte-identical confirmation instead of creating a second grant.
        let approved_replay = enroll_request(
            &invite,
            public,
            random_urlsafe(NONCE_BYTES),
            "enroll-operation-1",
            "Phone",
        );
        let approved_challenge = reloaded
            .issue_challenge(&approved_replay, "phone")
            .await
            .unwrap();
        let approved_proof = sign_request(
            &approved_replay,
            &approved_challenge,
            &key,
            &host_id,
            "phone",
        );
        assert_eq!(
            reloaded
                .enroll_at(
                    &approved_replay,
                    &approved_challenge,
                    &approved_proof,
                    &host_id,
                    "phone",
                    now + 3,
                )
                .await
                .unwrap(),
            EnrollmentOutcomeV2::Enrolled { enrolled }
        );
    }

    #[test]
    fn replay_and_connection_caches_are_strictly_bounded() {
        let mut cache = RecentNonceCache::default();
        for subject in 0..(MAX_RECENT_NONCE_SUBJECTS + 7) {
            assert!(cache.record(&format!("subject-{subject}"), "nonce-0"));
        }
        assert_eq!(cache.subjects.len(), MAX_RECENT_NONCE_SUBJECTS);
        assert_eq!(cache.lru.len(), MAX_RECENT_NONCE_SUBJECTS);
        assert!(!cache.subjects.contains_key("subject-0"));
        assert!(!cache.record("subject-7", "nonce-0"));

        for nonce in 1..=MAX_RECENT_CLIENT_NONCES {
            assert!(cache.record("subject-7", &format!("nonce-{nonce}")));
        }
        let subject = &cache.subjects["subject-7"];
        assert_eq!(subject.len(), MAX_RECENT_CLIENT_NONCES);
        assert!(!subject.contains(&"nonce-0".to_string()));

        assert!(active_connection_capacity_allows(0..7, 7));
        assert!(active_connection_capacity_allows(0..8, 7));
        assert!(!active_connection_capacity_allows(0..8, 8));
        assert!(retain_requesting_revocation_connection(7, 7));
        assert!(!retain_requesting_revocation_connection(6, 7));
    }

    #[test]
    fn nested_resume_fields_and_restart_responses_have_exact_wire_shapes() {
        let unknown_resume = r#"{"op":"connect","v":2,"credential_id":"AgICAgICAgICAgICAgICAg","client_nonce":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI","agent":"codex","resume":{"last_seq":7,"unexpected":true}}"#;
        assert!(serde_json::from_str::<RequestV2>(unknown_resume).is_err());

        let result = RestartResultV2 {
            agent: "codex".to_string(),
            idempotency_key: "restart-operation-0001".to_string(),
            command_sequence: 1,
            status: RestartStatusV2::Succeeded,
        };
        assert_eq!(
            serde_json::to_value(ResponseV2::restart(result.clone())).unwrap(),
            serde_json::json!({
                "v": 2,
                "ok": true,
                "restart": {
                    "agent": "codex",
                    "idempotency_key": "restart-operation-0001",
                    "command_sequence": 1,
                    "status": "succeeded"
                }
            })
        );
        assert_eq!(
            serde_json::to_value(ResponseV2::restart(RestartResultV2 {
                status: RestartStatusV2::OutcomeUnknown,
                ..result
            }))
            .unwrap(),
            serde_json::json!({
                "v": 2,
                "ok": false,
                "restart": {
                    "agent": "codex",
                    "idempotency_key": "restart-operation-0001",
                    "command_sequence": 1,
                    "status": "outcome_unknown"
                },
                "error_code": "outcome_unknown",
                "error": "operation outcome unknown"
            })
        );
    }

    #[test]
    fn loaded_invitation_integrity_rejects_clock_rollback_and_corrupt_claims() {
        let now = 10_000;
        let base = InvitationRecord {
            invitation_id: "future".to_string(),
            secret_hash: "00".repeat(32),
            created_at: now + 1,
            expires_at: now + 301,
            max_runtime_ids: vec!["codex".to_string()],
            max_scopes: vec![DeviceScopeV2::ConnectRuntime, DeviceScopeV2::SelfRevoke],
            confirmation_mode: ConfirmationModeV2::Interactive,
            claim: None,
            terminal_at: None,
        };
        let mut invalid_lifetime = base.clone();
        invalid_lifetime.invitation_id = "invalid-lifetime".to_string();
        invalid_lifetime.created_at = now - 1;
        invalid_lifetime.expires_at = now + DEFAULT_INVITATION_TTL.as_secs() as i64;

        let mut invalid_claim = base.clone();
        invalid_claim.invitation_id = "invalid-claim".to_string();
        invalid_claim.created_at = now - 10;
        invalid_claim.expires_at = now + 10;
        invalid_claim.claim = Some(EnrollmentClaimRecord {
            claim_id: "claim".to_string(),
            credential_id: "credential".to_string(),
            idempotency_key: "enroll-operation-1".to_string(),
            request_fingerprint: "fingerprint".to_string(),
            endpoint_id: "phone".to_string(),
            device_public_key: "key".to_string(),
            display_name: "Phone".to_string(),
            selected_runtime_ids: vec!["codex".to_string()],
            requested_scopes: vec![DeviceScopeV2::ConnectRuntime, DeviceScopeV2::SelfRevoke],
            sas: "000-000".to_string(),
            transcript_hash: "hash".to_string(),
            created_at: now - 11,
            expires_at: now + 9,
            auth_epoch: 0,
            status: ClaimStatus::Pending,
        });

        let mut state = PersistedState::default();
        state.invitations.insert("future".to_string(), base);
        state
            .invitations
            .insert("invalid-lifetime".to_string(), invalid_lifetime);
        state
            .invitations
            .insert("invalid-claim".to_string(), invalid_claim);
        sanitize_loaded_invitations(&mut state, now);

        assert!(
            state
                .invitations
                .values()
                .all(|invitation| invitation.terminal_at == Some(now))
        );
        assert_eq!(
            state.invitations["invalid-claim"]
                .claim
                .as_ref()
                .unwrap()
                .status,
            ClaimStatus::Rejected
        );
    }

    #[tokio::test]
    async fn bogus_revocations_do_not_grow_operation_gates() {
        let (_temp, manager) = manager().await;
        let host_id = iroh::SecretKey::generate().public().to_string();
        let (key, _) = signing_key_and_public();
        for index in 0..64 {
            let credential_id = random_urlsafe(DEVICE_ID_BYTES);
            assert!(
                manager
                    .revoke_device(&credential_id)
                    .await
                    .unwrap()
                    .is_none()
            );
            let request = RequestV2::RevokeSelf {
                v: PROTOCOL_VERSION_V2,
                credential_id: credential_id.clone(),
                client_nonce: random_urlsafe(NONCE_BYTES),
                idempotency_key: format!("bogus-revoke-{index}"),
            };
            let challenge = ProofChallengeV2::issue(credential_id, 0);
            let proof = sign_request(&request, &challenge, &key, &host_id, "phone");
            assert_eq!(
                manager
                    .revoke_mutation(
                        &request,
                        ProofExchange {
                            challenge: &challenge,
                            proof: &proof,
                            host_endpoint_id: &host_id,
                            client_endpoint_id: "phone",
                        },
                        unix_now(),
                        false,
                    )
                    .await,
                Err(RedeemError::Unavailable)
            );
        }
        assert!(manager.operation_gates.lock().await.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn enrollment_commit_unknown_is_applied_and_exact_replay_recovers() {
        let (temp, manager) = manager().await;
        let now = unix_now();
        let (host_id, invite) = invitation(&manager, policy(), now).await;
        let (key, public) = signing_key_and_public();
        let request = enroll_request(
            &invite,
            public.clone(),
            random_urlsafe(NONCE_BYTES),
            "enroll-operation-1",
            "Phone",
        );
        let challenge = manager.issue_challenge(&request, "phone").await.unwrap();
        let proof = sign_request(&request, &challenge, &key, &host_id, "phone");
        let marker = temp.path().join(".force-remora-link-dir-sync-failure");
        tokio::fs::write(&marker, b"fail after rename")
            .await
            .unwrap();

        assert_eq!(
            manager
                .enroll_at(&request, &challenge, &proof, &host_id, "phone", now + 1,)
                .await,
            Err(RedeemError::DurabilityUnknown)
        );
        let pending = manager.state.lock().await.invitations[&invite.invitation_id]
            .claim
            .as_ref()
            .unwrap()
            .pending();
        assert!(manager.durability_unknown.load(Ordering::Acquire));

        // Replay protection precedes any second mutation attempt.
        assert_eq!(
            manager
                .enroll_at(&request, &challenge, &proof, &host_id, "phone", now + 1,)
                .await,
            Err(RedeemError::Unavailable)
        );

        let replay = enroll_request(
            &invite,
            public.clone(),
            random_urlsafe(NONCE_BYTES),
            "enroll-operation-1",
            "Phone",
        );
        let replay_challenge = manager.issue_challenge(&replay, "phone").await.unwrap();
        assert_eq!(replay_challenge.credential_id, pending.credential_id);
        let replay_proof = sign_request(&replay, &replay_challenge, &key, &host_id, "phone");
        assert_eq!(
            manager
                .enroll_at(
                    &replay,
                    &replay_challenge,
                    &replay_proof,
                    &host_id,
                    "phone",
                    now + 2,
                )
                .await,
            Err(RedeemError::DurabilityUnknown)
        );

        tokio::fs::remove_file(marker).await.unwrap();
        let recovered = enroll_request(
            &invite,
            public,
            random_urlsafe(NONCE_BYTES),
            "enroll-operation-1",
            "Phone",
        );
        let recovered_challenge = manager.issue_challenge(&recovered, "phone").await.unwrap();
        let recovered_proof =
            sign_request(&recovered, &recovered_challenge, &key, &host_id, "phone");
        assert_eq!(
            manager
                .enroll_at(
                    &recovered,
                    &recovered_challenge,
                    &recovered_proof,
                    &host_id,
                    "phone",
                    now + 3,
                )
                .await
                .unwrap(),
            EnrollmentOutcomeV2::Pending { pending }
        );
        assert!(!manager.durability_unknown.load(Ordering::Acquire));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn revocation_and_restart_replays_preserve_outcome_under_unknown_durability() {
        let (temp, manager) = manager().await;
        let now = unix_now();
        let (host_id, key, enrolled) = approve_test_device(&manager, now).await;

        let (restart, authorization) = authorize_restart_request(
            &manager,
            &host_id,
            &key,
            &enrolled,
            "restart-operation-1",
            1,
            now + 2,
        )
        .await;
        let dispatch = match manager
            .prepare_restart(&restart, &authorization, "phone", true)
            .await
            .unwrap()
        {
            RestartPreparationV2::Execute(dispatch) => dispatch,
            other => panic!("expected restart dispatch, got {other:?}"),
        };
        assert_eq!(
            manager
                .mark_restart_succeeded(&dispatch)
                .await
                .unwrap()
                .status,
            RestartStatusV2::Succeeded
        );
        drop(dispatch);

        let marker = temp.path().join(".force-remora-link-dir-sync-failure");
        tokio::fs::write(&marker, b"fail after rename")
            .await
            .unwrap();
        assert!(
            manager
                .create_invitation_at(
                    host_id.clone(),
                    Some("Development Mac".to_string()),
                    None,
                    policy(),
                    now + 3,
                )
                .await
                .is_err()
        );
        assert!(manager.durability_unknown.load(Ordering::Acquire));

        let (restart_replay, replay_authorization) = authorize_restart_request(
            &manager,
            &host_id,
            &key,
            &enrolled,
            "restart-operation-1",
            1,
            now + 4,
        )
        .await;
        assert!(matches!(
            manager
                .prepare_restart(&restart_replay, &replay_authorization, "phone", true)
                .await
                .unwrap(),
            RestartPreparationV2::OutcomeUnknown(RestartResultV2 {
                command_sequence: 1,
                ..
            })
        ));
        assert_eq!(manager.state.lock().await.restart_commands.len(), 1);

        tokio::fs::remove_file(&marker).await.unwrap();
        let (restart_recovered, recovered_authorization) = authorize_restart_request(
            &manager,
            &host_id,
            &key,
            &enrolled,
            "restart-operation-1",
            1,
            now + 5,
        )
        .await;
        assert!(matches!(
            manager
                .prepare_restart(&restart_recovered, &recovered_authorization, "phone", false,)
                .await
                .unwrap(),
            RestartPreparationV2::Succeeded(RestartResultV2 {
                command_sequence: 1,
                ..
            })
        ));

        let revoke = RequestV2::RevokeSelf {
            v: PROTOCOL_VERSION_V2,
            credential_id: enrolled.device_id.clone(),
            client_nonce: random_urlsafe(NONCE_BYTES),
            idempotency_key: "self-revoke-operation-1".to_string(),
        };
        let challenge = ProofChallengeV2::issue_at(enrolled.device_id.clone(), 0, now + 6);
        let proof = sign_request(&revoke, &challenge, &key, &host_id, "phone");
        tokio::fs::write(&marker, b"fail after rename")
            .await
            .unwrap();
        let first = manager
            .revoke_mutation(
                &revoke,
                ProofExchange {
                    challenge: &challenge,
                    proof: &proof,
                    host_endpoint_id: &host_id,
                    client_endpoint_id: "phone",
                },
                now + 6,
                false,
            )
            .await
            .unwrap();
        let RevocationMutationV2::OutcomeUnknown(receipt) = first else {
            panic!("expected outcome-unknown revocation")
        };

        let replay = RequestV2::RevokeSelf {
            v: PROTOCOL_VERSION_V2,
            credential_id: enrolled.device_id.clone(),
            client_nonce: random_urlsafe(NONCE_BYTES),
            idempotency_key: "self-revoke-operation-1".to_string(),
        };
        let replay_challenge = ProofChallengeV2::issue_at(enrolled.device_id.clone(), 1, now + 7);
        let replay_proof = sign_request(&replay, &replay_challenge, &key, &host_id, "phone");
        assert_eq!(
            manager
                .revoke_mutation(
                    &replay,
                    ProofExchange {
                        challenge: &replay_challenge,
                        proof: &replay_proof,
                        host_endpoint_id: &host_id,
                        client_endpoint_id: "phone",
                    },
                    now + 7,
                    false,
                )
                .await
                .unwrap(),
            RevocationMutationV2::OutcomeUnknown(receipt.clone())
        );

        tokio::fs::remove_file(marker).await.unwrap();
        let recovered = RequestV2::RevokeSelf {
            v: PROTOCOL_VERSION_V2,
            credential_id: enrolled.device_id.clone(),
            client_nonce: random_urlsafe(NONCE_BYTES),
            idempotency_key: "self-revoke-operation-1".to_string(),
        };
        let recovered_challenge = ProofChallengeV2::issue_at(enrolled.device_id, 1, now + 8);
        let recovered_proof =
            sign_request(&recovered, &recovered_challenge, &key, &host_id, "phone");
        assert_eq!(
            manager
                .revoke_mutation(
                    &recovered,
                    ProofExchange {
                        challenge: &recovered_challenge,
                        proof: &recovered_proof,
                        host_endpoint_id: &host_id,
                        client_endpoint_id: "phone",
                    },
                    now + 8,
                    false,
                )
                .await
                .unwrap(),
            RevocationMutationV2::Durable(receipt)
        );
        assert!(!manager.durability_unknown.load(Ordering::Acquire));
    }

    #[test]
    fn noncanonical_and_unknown_scope_frames_fail_closed() {
        let json = r#"{"op":"enroll","v":2,"invitation_id":"abcdefghijklmnopqrstuv","secret":"x","device_name":"Phone","device_public_key":"x","selected_runtime_ids":["codex"],"requested_scopes":["unknown_scope"],"idempotency_key":"operation-1","client_nonce":"x"}"#.to_string();
        assert!(serde_json::from_str::<RequestV2>(&json).is_err());
        assert!(
            validate_grant(
                &["codex".to_string(), "codex".to_string()],
                &[DeviceScopeV2::ConnectRuntime, DeviceScopeV2::SelfRevoke]
            )
            .is_err()
        );
    }

    #[test]
    fn proof_and_sas_golden_vectors() {
        let host_endpoint_id = iroh::SecretKey::from_bytes(&[0x61_u8; 32])
            .public()
            .to_string();
        let client_endpoint_id = iroh::SecretKey::from_bytes(&[0x62_u8; 32])
            .public()
            .to_string();
        let credential_id = URL_SAFE_NO_PAD.encode([0x02_u8; 16]);
        let challenge_id = URL_SAFE_NO_PAD.encode([0x03_u8; 16]);
        let invitation_id = URL_SAFE_NO_PAD.encode([0x01_u8; 16]);
        let claim_id = URL_SAFE_NO_PAD.encode([0x04_u8; 16]);
        let signing_key = SigningKey::from_slice(&[0x07_u8; 32]).unwrap();
        let device_public_key = URL_SAFE_NO_PAD.encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let device_key_hash = Sha256::digest(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .into();
        let list_request = RequestV2::ListAgents {
            v: PROTOCOL_VERSION_V2,
            credential_id: credential_id.clone(),
            client_nonce: URL_SAFE_NO_PAD.encode([0x22_u8; 32]),
        };
        let payload_hash = list_request.operation_payload_hash();
        let server_nonce = URL_SAFE_NO_PAD.encode([0x11_u8; 32]);
        let client_nonce = URL_SAFE_NO_PAD.encode([0x22_u8; 32]);
        let transcript = encode_proof_transcript(&ProofTranscript {
            host_endpoint_id: &host_endpoint_id,
            client_endpoint_id: &client_endpoint_id,
            operation: "list_agents",
            credential_id: &credential_id,
            auth_epoch: 7,
            device_key_hash: &device_key_hash,
            challenge_id: &challenge_id,
            server_nonce: &server_nonce,
            client_nonce: &client_nonce,
            operation_payload_hash: &payload_hash,
        })
        .unwrap();
        let proof_transcript_hex = hex::encode(&transcript);
        let proof_transcript_sha256 = hex::encode(Sha256::digest(&transcript));
        let payload_hash_hex = hex::encode(payload_hash);

        let selected_runtime_ids = vec!["codex".to_string()];
        let requested_scopes = vec![
            DeviceScopeV2::InspectRuntimes,
            DeviceScopeV2::ConnectRuntime,
            DeviceScopeV2::SelfRevoke,
        ];
        let max_runtime_ids = vec!["claude".to_string(), "codex".to_string()];
        let max_scopes = vec![
            DeviceScopeV2::InspectRuntimes,
            DeviceScopeV2::ConnectRuntime,
            DeviceScopeV2::RestartRuntime,
            DeviceScopeV2::SelfRevoke,
        ];
        let enrollment_input = EnrollmentTranscriptInput {
            host_endpoint_id: &host_endpoint_id,
            client_endpoint_id: &client_endpoint_id,
            invitation_id: &invitation_id,
            device_public_key: &device_public_key,
            idempotency_key: "enroll-operation-0001",
            selected_runtime_ids: &selected_runtime_ids,
            requested_scopes: &requested_scopes,
            server_nonce: &server_nonce,
            client_nonce: &client_nonce,
            confirmation_mode: ConfirmationModeV2::Interactive,
            max_runtime_ids: &max_runtime_ids,
            max_scopes: &max_scopes,
        };
        let enrollment_transcript = encode_enrollment_transcript(enrollment_input).unwrap();
        let enrollment_hash = enrollment_transcript_hash(enrollment_input).unwrap();
        let policy_transcript =
            encode_host_policy_transcript(&max_runtime_ids, &max_scopes).unwrap();
        let policy_digest = host_policy_digest(&max_runtime_ids, &max_scopes).unwrap();
        let secret = URL_SAFE_NO_PAD.encode([0x44_u8; 32]);
        let enrollment_hash_hex = hex::encode(enrollment_hash);
        let sas = derive_sas(&secret, &enrollment_hash);
        let signature: Signature = signing_key.sign(&transcript);
        let signature_der = URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes());

        let mut prospective_credential_material = Vec::new();
        prospective_credential_material.extend_from_slice(PROSPECTIVE_CREDENTIAL_DOMAIN);
        for field in [
            invitation_id.as_bytes(),
            client_endpoint_id.as_bytes(),
            device_public_key.as_bytes(),
            b"enroll-operation-0001",
        ] {
            append_field(&mut prospective_credential_material, field).unwrap();
        }
        let prospective_credential_digest = Sha256::digest(&prospective_credential_material);
        let prospective_id =
            URL_SAFE_NO_PAD.encode(&prospective_credential_digest[..DEVICE_ID_BYTES]);
        assert_eq!(
            prospective_id,
            prospective_credential_id(
                &invitation_id,
                &client_endpoint_id,
                &device_public_key,
                "enroll-operation-0001",
            )
            .unwrap()
        );

        let restart_request = RequestV2::RestartAgent {
            v: PROTOCOL_VERSION_V2,
            credential_id: credential_id.clone(),
            client_nonce: client_nonce.clone(),
            agent: "codex".to_string(),
            idempotency_key: "restart-operation-0001".to_string(),
            command_sequence: 1,
        };
        let restart_payload_hash = restart_request.operation_payload_hash();
        let restart_transcript = encode_proof_transcript(&ProofTranscript {
            host_endpoint_id: &host_endpoint_id,
            client_endpoint_id: &client_endpoint_id,
            operation: "restart_agent",
            credential_id: &credential_id,
            auth_epoch: 7,
            device_key_hash: &device_key_hash,
            challenge_id: &challenge_id,
            server_nonce: &server_nonce,
            client_nonce: &client_nonce,
            operation_payload_hash: &restart_payload_hash,
        })
        .unwrap();
        let restart_signature: Signature = signing_key.sign(&restart_transcript);
        let restart_signature_der = URL_SAFE_NO_PAD.encode(restart_signature.to_der().as_bytes());
        let restart_result = RestartResultV2 {
            agent: "codex".to_string(),
            idempotency_key: "restart-operation-0001".to_string(),
            command_sequence: 1,
            status: RestartStatusV2::Succeeded,
        };
        let restart_succeeded_response =
            serde_json::to_string(&ResponseV2::restart(restart_result.clone())).unwrap();
        let restart_outcome_unknown_response =
            serde_json::to_string(&ResponseV2::restart(RestartResultV2 {
                status: RestartStatusV2::OutcomeUnknown,
                ..restart_result
            }))
            .unwrap();
        assert_eq!(
            host_endpoint_id,
            "af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d"
        );
        assert_eq!(
            client_endpoint_id,
            "2df04125f0015afb47ce853aef8772094ff9498c14cb1b9e12973c2927da0fa6"
        );
        assert_eq!(
            device_public_key,
            "BB4YUy_UdUwC8wQdnHXOszuD_9gax85P6ILMscmLxYlupGwxHE4v9A3ZajZT5uRURdMt_khuztdcepDGoYiBwKM"
        );
        assert_eq!(
            payload_hash_hex,
            "42151db40bc779d55edc20fc6cefd8580eec3e37854e648c83910458af7fb734"
        );
        assert_eq!(
            proof_transcript_hex,
            "72656d6f72612d6c696e6b2f322f70726f6f662f763200000004000000020000000d72656d6f72612d6c696e6b2f32000000406166303661336533323931373134653466333536633139633962313563643139353165633665363636326161373762653037353437663238393338333334316400000040326466303431323566303031356166623437636538353361656638373732303934666639343938633134636231623965313239373363323932376461306661360000000b6c6973745f6167656e7473000000164167494341674943416749434167494341674943416700000008000000000000000700000020c8f193e678e762f9c4b28fc9e11a6e43d5cd792d2e1e376e56b80a76f22744ac0000001641774d4441774d4441774d4441774d4441774d4441770000002b455245524552455245524552455245524552455245524552455245524552455245524552455245524552450000002b496949694969496949694969496949694969496949694969496949694969496949694969496949694969490000002042151db40bc779d55edc20fc6cefd8580eec3e37854e648c83910458af7fb734"
        );
        assert_eq!(
            proof_transcript_sha256,
            "a3a0262ed8cb684fea0691e61b74c35f4e0b1422a065bb7bc647f905d296f8ae"
        );
        assert_eq!(
            enrollment_hash_hex,
            "bc6607fa748761afc8694f55e736f58d71cf46ae685699de16ad6f7ace9f1878"
        );
        assert_eq!(sas, "N3N-FY1");
        assert_eq!(
            signature_der,
            "MEUCIA1jjLu3EUSEj2880Pk7IuEgmcF5TmgK_KMNyMKqJYlmAiEAi22sPZkFhV0XsBhmrNdHNmtMRcZi1xXnW-euHOUm1zA"
        );
        assert_eq!(
            derive_sas(&URL_SAFE_NO_PAD.encode([0x44_u8; 32]), &[0x55_u8; 32]),
            "3PT-GWZ"
        );

        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/remora-link-v2/golden-vectors.json"
        ))
        .unwrap();
        assert_eq!(fixture["schema_version"], 1);
        assert_eq!(
            fixture["protocol"],
            serde_json::json!({
                "wire_version": PROTOCOL_VERSION_V2,
                "alpn": std::str::from_utf8(REMORA_LINK_ALPN).unwrap(),
                "proof_domain": std::str::from_utf8(PROOF_TRANSCRIPT_DOMAIN).unwrap(),
                "payload_domain": std::str::from_utf8(OPERATION_PAYLOAD_DOMAIN).unwrap(),
                "enrollment_domain": std::str::from_utf8(ENROLLMENT_TRANSCRIPT_DOMAIN).unwrap(),
                "policy_domain": std::str::from_utf8(POLICY_DIGEST_DOMAIN).unwrap(),
                "prospective_credential_domain": std::str::from_utf8(PROSPECTIVE_CREDENTIAL_DOMAIN).unwrap(),
                "sas_domain": std::str::from_utf8(SAS_DOMAIN).unwrap(),
                "frame_length_encoding": "u32be",
                "binary_json_encoding": "base64url-no-pad"
            })
        );

        let list_request_json = serde_json::to_string(&list_request).unwrap();
        let prospective_material_hex = hex::encode(&prospective_credential_material);
        let prospective_digest_hex = hex::encode(prospective_credential_digest);
        let restart_request_json = serde_json::to_string(&restart_request).unwrap();
        let restart_payload_hash_hex = hex::encode(restart_payload_hash);
        let restart_transcript_hex = hex::encode(&restart_transcript);
        let restart_transcript_sha256_hex = hex::encode(Sha256::digest(&restart_transcript));
        let policy_transcript_hex = hex::encode(policy_transcript);
        let policy_digest_hex = hex::encode(policy_digest);
        let enrollment_transcript_hex = hex::encode(enrollment_transcript);
        let enrollment_hash_base64url = URL_SAFE_NO_PAD.encode(enrollment_hash);
        let expected_inputs = serde_json::json!({
            "host_iroh_secret_key_hex": hex::encode([0x61_u8; 32]),
            "host_iroh_endpoint_id": host_endpoint_id,
            "client_iroh_secret_key_hex": hex::encode([0x62_u8; 32]),
            "client_iroh_endpoint_id": client_endpoint_id,
            "p256_private_key_hex": hex::encode([0x07_u8; 32]),
            "device_public_key_sec1_base64url": device_public_key,
            "device_public_key_sha256_hex": hex::encode(device_key_hash),
            "invitation_id": invitation_id,
            "credential_id": credential_id,
            "challenge_id": challenge_id,
            "claim_id": claim_id,
            "server_nonce": server_nonce,
            "client_nonce": client_nonce,
            "invitation_secret_hex": hex::encode([0x44_u8; 32]),
            "invitation_secret_base64url": secret,
            "operation": list_request.operation(),
            "auth_epoch": 7,
            "restart_agent": "codex",
            "restart_idempotency_key": "restart-operation-0001",
            "restart_command_sequence": 1,
            "enrollment_idempotency_key": "enroll-operation-0001",
            "selected_runtime_ids": selected_runtime_ids,
            "requested_scopes": requested_scopes,
            "confirmation_mode": ConfirmationModeV2::Interactive,
            "max_runtime_ids": max_runtime_ids,
            "max_scopes": max_scopes
        });
        assert_eq!(
            fixture["vector"],
            serde_json::json!({
                "inputs": expected_inputs,
                "prospective_credential_material_hex": prospective_material_hex,
                "prospective_credential_sha256_hex": prospective_digest_hex,
                "prospective_credential_id": prospective_id,
                "list_agents_request_json": list_request_json,
                "operation_payload_sha256_hex": payload_hash_hex,
                "proof_transcript_hex": proof_transcript_hex,
                "proof_transcript_sha256_hex": proof_transcript_sha256,
                "proof_signature_der_base64url": signature_der,
                "restart_request_json": restart_request_json,
                "restart_operation_payload_sha256_hex": restart_payload_hash_hex,
                "restart_proof_transcript_hex": restart_transcript_hex,
                "restart_proof_transcript_sha256_hex": restart_transcript_sha256_hex,
                "restart_proof_signature_der_base64url": restart_signature_der,
                "restart_succeeded_response_json": restart_succeeded_response,
                "restart_outcome_unknown_response_json": restart_outcome_unknown_response,
                "host_policy_transcript_hex": policy_transcript_hex,
                "host_policy_digest_sha256_hex": policy_digest_hex,
                "enrollment_transcript_hex": enrollment_transcript_hex,
                "enrollment_transcript_sha256_hex": enrollment_hash_hex,
                "enrollment_transcript_sha256_base64url": enrollment_hash_base64url,
                "sas": sas
            })
        );
        let standalone_hash = [0x55_u8; 32];
        assert_eq!(
            fixture["standalone_sas_vector"],
            serde_json::json!({
                "invitation_secret_base64url": URL_SAFE_NO_PAD.encode([0x44_u8; 32]),
                "enrollment_transcript_sha256_hex": hex::encode(standalone_hash),
                "sas": derive_sas(
                    &URL_SAFE_NO_PAD.encode([0x44_u8; 32]),
                    &standalone_hash,
                )
            })
        );
    }
}
