//! Remora Link pairing protocol v2.
//!
//! V1 authenticates every client with one host-global bearer token. V2 is a
//! separate ALPN and deliberately has no token-upgrade path: a short-lived,
//! one-time invitation may enroll exactly the authenticated Iroh endpoint
//! that redeemed it. Subsequent streams are authorized by that endpoint's
//! durable device grant.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
use tokio::sync::Mutex;
use tracing::{error, warn};

use crate::protocol::{AgentInfo, Resume, SessionInfo};

pub const PROTOCOL_VERSION_V2: u32 = 2;
pub const REMORA_LINK_ALPN: &[u8] = b"remora-link/2";
pub const PAIRING_CODE_PREFIX: &str = "remora-link:v2:";
pub const DEFAULT_INVITATION_TTL: Duration = Duration::from_secs(5 * 60);

const STORE_VERSION: u32 = 2;
const INVITATION_ID_BYTES: usize = 16;
const INVITATION_SECRET_BYTES: usize = 32;
const DEVICE_ID_BYTES: usize = 16;
const MAX_OPEN_INVITATIONS: usize = 16;
const TOMBSTONE_RETENTION_SECS: i64 = 90 * 24 * 60 * 60;
const SECRET_HASH_DOMAIN: &[u8] = b"remora-link/pairing-v2/invitation-secret\0";
pub const PROOF_TRANSCRIPT_DOMAIN: &[u8] = b"remora-link/2/proof/v1";
pub const OPERATION_PAYLOAD_DOMAIN: &[u8] = b"remora-link/2/payload/v1";
const NONCE_BYTES: usize = 32;
const CHALLENGE_ID_BYTES: usize = 16;
const CHALLENGE_TTL: Duration = Duration::from_secs(30);
const MAX_RECENT_CLIENT_NONCES: usize = 256;

/// JSON encoded into the QR code. The invitation secret is never written to
/// host storage; only its domain-separated SHA-256 digest is persisted.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairingInvitation {
    pub v: u32,
    pub node_id: String,
    pub invitation_id: String,
    pub secret: String,
    pub expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
}

impl PairingInvitation {
    /// Copy/paste and QR representation. This retains the full 256-bit
    /// invitation secret and authenticated host route; it is not a shortened
    /// or lower-entropy pairing authenticator.
    pub fn to_pairing_code(&self) -> anyhow::Result<String> {
        let json = serde_json::to_vec(self).context("serializing pairing invitation")?;
        Ok(format!(
            "{PAIRING_CODE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(json)
        ))
    }

    pub fn from_pairing_code(code: &str) -> anyhow::Result<Self> {
        let encoded = code
            .trim()
            .strip_prefix(PAIRING_CODE_PREFIX)
            .ok_or_else(|| anyhow!("unsupported pairing code"))?;
        if encoded.len() > 4096 {
            return Err(anyhow!("pairing code is too large"));
        }
        let json = URL_SAFE_NO_PAD
            .decode(encoded)
            .context("decoding pairing code")?;
        let invitation: Self =
            serde_json::from_slice(&json).context("parsing pairing invitation")?;
        if invitation.v != PROTOCOL_VERSION_V2 {
            return Err(anyhow!("unsupported pairing protocol version"));
        }
        let invitation_id = URL_SAFE_NO_PAD
            .decode(&invitation.invitation_id)
            .context("decoding invitation id")?;
        let secret = URL_SAFE_NO_PAD
            .decode(&invitation.secret)
            .context("decoding invitation secret")?;
        if invitation_id.len() != INVITATION_ID_BYTES
            || secret.len() != INVITATION_SECRET_BYTES
            || invitation.expires_at <= unix_now()
            || invitation.node_id.parse::<iroh::PublicKey>().is_err()
            || invitation
                .host_name
                .as_ref()
                .is_some_and(|name| name.len() > 255 || name.chars().any(char::is_control))
            || invitation
                .relay
                .as_ref()
                .is_some_and(|relay| relay.parse::<iroh::RelayUrl>().is_err())
        {
            return Err(anyhow!("invalid or expired pairing invitation"));
        }
        Ok(invitation)
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
            .field("host_name", &self.host_name)
            .field("relay", &self.relay)
            .finish()
    }
}

/// First frame on every `remora-link/2` bi-stream. There is intentionally no
/// bearer-token field and unknown fields are rejected, so a v1 token cannot
/// be smuggled into an upgrade request.
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestV2 {
    Enroll {
        v: u32,
        invitation_id: String,
        secret: String,
        #[serde(default)]
        device_name: String,
        /// Base64url-no-pad SEC1/X9.63 uncompressed P-256 public key (65 bytes).
        device_public_key: String,
        /// Base64url-no-pad 32-byte fresh random nonce.
        client_nonce: String,
    },
    ListAgents {
        v: u32,
        credential_id: String,
        client_nonce: String,
    },
    RestartAgent {
        v: u32,
        credential_id: String,
        client_nonce: String,
        agent: String,
    },
    Connect {
        v: u32,
        credential_id: String,
        client_nonce: String,
        agent: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resume: Option<Resume>,
    },
}

impl RequestV2 {
    pub fn version(&self) -> u32 {
        match self {
            Self::Enroll { v, .. }
            | Self::ListAgents { v, .. }
            | Self::RestartAgent { v, .. }
            | Self::Connect { v, .. } => *v,
        }
    }

    pub fn operation(&self) -> &'static str {
        match self {
            Self::Enroll { .. } => "enroll",
            Self::ListAgents { .. } => "list_agents",
            Self::RestartAgent { .. } => "restart_agent",
            Self::Connect { .. } => "connect",
        }
    }

    pub fn client_nonce(&self) -> &str {
        match self {
            Self::Enroll { client_nonce, .. }
            | Self::ListAgents { client_nonce, .. }
            | Self::RestartAgent { client_nonce, .. }
            | Self::Connect { client_nonce, .. } => client_nonce,
        }
    }

    pub fn credential_id(&self) -> Option<&str> {
        match self {
            Self::Enroll { .. } => None,
            Self::ListAgents { credential_id, .. }
            | Self::RestartAgent { credential_id, .. }
            | Self::Connect { credential_id, .. } => Some(credential_id),
        }
    }

    pub fn operation_payload_hash(&self) -> [u8; 32] {
        match self {
            Self::Enroll {
                invitation_id,
                secret,
                device_name,
                device_public_key,
                ..
            } => hash_operation_payload(&[invitation_id, secret, device_name, device_public_key]),
            Self::ListAgents { .. } => hash_operation_payload(&[]),
            Self::RestartAgent { agent, .. } => hash_operation_payload(&[agent]),
            Self::Connect { agent, resume, .. } => {
                let cursor = resume
                    .as_ref()
                    .map(|resume| resume.last_seq.to_string())
                    .unwrap_or_default();
                hash_operation_payload(&[agent, &cursor])
            }
        }
    }
}

impl fmt::Debug for RequestV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enroll {
                v,
                invitation_id,
                device_name,
                ..
            } => f
                .debug_struct("Enroll")
                .field("v", v)
                .field("invitation_id", invitation_id)
                .field("secret", &"[REDACTED]")
                .field("device_name", device_name)
                .finish(),
            Self::ListAgents {
                v, credential_id, ..
            } => f
                .debug_struct("ListAgents")
                .field("v", v)
                .field("credential_id", credential_id)
                .field("client_nonce", &"[REDACTED]")
                .finish(),
            Self::RestartAgent { v, agent, .. } => f
                .debug_struct("RestartAgent")
                .field("v", v)
                .field("client_nonce", &"[REDACTED]")
                .field("agent", agent)
                .finish(),
            Self::Connect {
                v, agent, resume, ..
            } => f
                .debug_struct("Connect")
                .field("v", v)
                .field("client_nonce", &"[REDACTED]")
                .field("agent", agent)
                .field("resume", resume)
                .finish(),
        }
    }
}

/// Host-generated challenge sent before any v2 enrollment or agent action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProofChallengeV2 {
    pub challenge_id: String,
    pub credential_id: String,
    pub server_nonce: String,
    pub expires_at: i64,
}

impl ProofChallengeV2 {
    pub fn issue(credential_id: String) -> Self {
        Self::issue_at(credential_id, unix_now())
    }

    fn issue_at(credential_id: String, now: i64) -> Self {
        Self {
            challenge_id: random_urlsafe(CHALLENGE_ID_BYTES),
            credential_id,
            server_nonce: random_urlsafe(NONCE_BYTES),
            expires_at: now.saturating_add(CHALLENGE_TTL.as_secs() as i64),
        }
    }
}

/// Second client frame on every v2 stream. Signatures use P-256 ECDSA with
/// SHA-256 and are encoded as base64url-no-pad ASN.1 DER, matching Apple
/// Secure Enclave and Android Keystore output.
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
    Internal,
}

impl ErrorCodeV2 {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::PairingUnavailable => "pairing unavailable",
            Self::AuthorizationRequired => "device authorization required",
            Self::InvalidRequest => "invalid request",
            Self::AgentUnavailable => "agent unavailable",
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
    pub created_at: i64,
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
    pub agents: Option<Vec<AgentInfo>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<ErrorCodeV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ResponseV2 {
    pub fn ok() -> Self {
        Self::success(None, None, None, None)
    }

    pub fn challenge(challenge: ProofChallengeV2) -> Self {
        Self::success(Some(challenge), None, None, None)
    }

    pub fn enrolled(device: EnrolledDevice) -> Self {
        Self::success(None, Some(device), None, None)
    }

    pub fn agents(agents: Vec<AgentInfo>) -> Self {
        Self::success(None, None, Some(agents), None)
    }

    pub fn session(session: SessionInfo) -> Self {
        Self::success(None, None, None, Some(session))
    }

    pub fn error(code: ErrorCodeV2) -> Self {
        Self {
            v: PROTOCOL_VERSION_V2,
            ok: false,
            challenge: None,
            enrolled: None,
            agents: None,
            session: None,
            error_code: Some(code),
            error: Some(code.message().to_string()),
        }
    }

    fn success(
        challenge: Option<ProofChallengeV2>,
        enrolled: Option<EnrolledDevice>,
        agents: Option<Vec<AgentInfo>>,
        session: Option<SessionInfo>,
    ) -> Self {
        Self {
            v: PROTOCOL_VERSION_V2,
            ok: true,
            challenge,
            enrolled,
            agents,
            session,
            error_code: None,
            error: None,
        }
    }
}

/// Redacted, stable local-control projection of a persisted device grant.
/// The raw Iroh endpoint id is intentionally omitted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceSummary {
    pub device_id: String,
    pub display_name: String,
    pub endpoint_fingerprint: String,
    pub device_key_fingerprint: String,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RedeemError {
    /// Deliberately coarsened across unknown, expired, consumed, malformed,
    /// revoked-endpoint, and persistence failures.
    #[error("pairing unavailable")]
    Unavailable,
}

#[derive(Clone)]
pub struct PairingManager {
    path: PathBuf,
    state: Arc<Mutex<PersistedState>>,
    active: Arc<Mutex<HashMap<String, Vec<Connection>>>>,
    recent_client_nonces: Arc<Mutex<HashMap<String, VecDeque<String>>>>,
}

impl PairingManager {
    pub async fn load_default() -> anyhow::Result<Self> {
        Self::load(crate::paths::pairing_v2_file()?).await
    }

    pub async fn load(path: PathBuf) -> anyhow::Result<Self> {
        let state = match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed: PersistedState = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing {}", path.display()))?;
                if parsed.version != STORE_VERSION {
                    return Err(anyhow!(
                        "unsupported pairing store version {} in {}",
                        parsed.version,
                        path.display()
                    ));
                }
                parsed
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => PersistedState::default(),
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", path.display()));
            }
        };
        Ok(Self {
            path,
            state: Arc::new(Mutex::new(state)),
            active: Arc::new(Mutex::new(HashMap::new())),
            recent_client_nonces: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Mint a high-entropy invitation. It is not a host-global credential and
    /// disappears from the active set after one successful redemption.
    pub async fn create_invitation(
        &self,
        node_id: String,
        host_name: Option<String>,
        relay: Option<String>,
    ) -> anyhow::Result<PairingInvitation> {
        self.create_invitation_at(node_id, host_name, relay, unix_now())
            .await
    }

    async fn create_invitation_at(
        &self,
        node_id: String,
        host_name: Option<String>,
        relay: Option<String>,
        now: i64,
    ) -> anyhow::Result<PairingInvitation> {
        let mut guard = self.state.lock().await;
        let mut next = guard.clone();
        sweep_expired(&mut next, now);

        while next.invitations.len() >= MAX_OPEN_INVITATIONS {
            let Some(oldest) = next
                .invitations
                .values()
                .min_by_key(|record| record.created_at)
                .map(|record| record.invitation_id.clone())
            else {
                break;
            };
            expire_invitation(&mut next, &oldest, now);
        }

        let invitation_id = unique_random_id(&next, INVITATION_ID_BYTES);
        let secret = random_urlsafe(INVITATION_SECRET_BYTES);
        let expires_at = now.saturating_add(DEFAULT_INVITATION_TTL.as_secs() as i64);
        next.invitations.insert(
            invitation_id.clone(),
            InvitationRecord {
                invitation_id: invitation_id.clone(),
                secret_hash: hex::encode(invitation_secret_hash(&secret)),
                created_at: now,
                expires_at,
            },
        );

        self.persist(&next).await?;
        *guard = next;
        Ok(PairingInvitation {
            v: PROTOCOL_VERSION_V2,
            node_id,
            invitation_id,
            secret,
            expires_at,
            host_name,
            relay,
        })
    }

    /// Issue a fresh server challenge. Unknown credential ids receive the same
    /// shape as known ones; authorization is decided only after proof.
    pub async fn issue_challenge(
        &self,
        request: &RequestV2,
    ) -> Result<ProofChallengeV2, RedeemError> {
        decode_nonce(request.client_nonce()).ok_or(RedeemError::Unavailable)?;
        let credential_id = match request.credential_id() {
            Some(id) if valid_opaque_id(id) => id.to_string(),
            Some(_) => return Err(RedeemError::Unavailable),
            None => {
                if let RequestV2::Enroll {
                    device_public_key, ..
                } = request
                {
                    parse_device_public_key(device_public_key)
                        .map_err(|_| RedeemError::Unavailable)?;
                }
                let state = self.state.lock().await;
                unique_device_id(&state)
            }
        };
        Ok(ProofChallengeV2::issue(credential_id))
    }

    /// Atomically verify proof-of-possession, consume an invitation, insert a
    /// device grant, and retain a replay tombstone. Both endpoint ids must come
    /// from the completed Iroh handshake/local endpoint, never request JSON.
    pub async fn redeem(
        &self,
        request: &RequestV2,
        challenge: &ProofChallengeV2,
        proof: &ProofV2,
        host_endpoint_id: &str,
        authenticated_client_endpoint_id: &str,
    ) -> Result<EnrolledDevice, RedeemError> {
        self.redeem_with_proof_at(
            request,
            challenge,
            proof,
            host_endpoint_id,
            authenticated_client_endpoint_id,
            unix_now(),
        )
        .await
    }

    async fn redeem_with_proof_at(
        &self,
        request: &RequestV2,
        challenge: &ProofChallengeV2,
        proof: &ProofV2,
        host_endpoint_id: &str,
        authenticated_client_endpoint_id: &str,
        now: i64,
    ) -> Result<EnrolledDevice, RedeemError> {
        let RequestV2::Enroll {
            invitation_id,
            secret,
            device_name,
            device_public_key,
            ..
        } = request
        else {
            return Err(RedeemError::Unavailable);
        };
        validate_challenge_proof(challenge, proof, now)?;
        if !valid_invitation_id(invitation_id)
            || secret.len() > 128
            || authenticated_client_endpoint_id.len() > 256
        {
            return Err(RedeemError::Unavailable);
        }

        let (verifying_key, key_bytes) =
            parse_device_public_key(device_public_key).map_err(|_| RedeemError::Unavailable)?;
        let key_hash = Sha256::digest(&key_bytes).into();
        let transcript = encode_proof_transcript(&ProofTranscript {
            host_endpoint_id,
            client_endpoint_id: authenticated_client_endpoint_id,
            operation: request.operation(),
            credential_id: &challenge.credential_id,
            device_key_hash: &key_hash,
            challenge_id: &challenge.challenge_id,
            server_nonce: &challenge.server_nonce,
            client_nonce: request.client_nonce(),
            operation_payload_hash: &request.operation_payload_hash(),
        })
        .map_err(|_| RedeemError::Unavailable)?;
        verify_signature(&verifying_key, &transcript, &proof.signature)?;

        let mut guard = self.state.lock().await;
        let mut next = guard.clone();
        sweep_expired(&mut next, now);

        let Some(invitation) = next.invitations.get(invitation_id).cloned() else {
            return Err(RedeemError::Unavailable);
        };
        if invitation.expires_at <= now
            || !secret_hash_matches(&invitation.secret_hash, secret)
            || next
                .devices
                .values()
                .any(|device| device.endpoint_id == authenticated_client_endpoint_id)
            || next.devices.contains_key(&challenge.credential_id)
        {
            return Err(RedeemError::Unavailable);
        }

        let display_name = normalize_device_name(device_name);
        let device = DeviceRecord {
            device_id: challenge.credential_id.clone(),
            endpoint_id: authenticated_client_endpoint_id.to_string(),
            device_public_key: device_public_key.clone(),
            display_name,
            created_at: now,
            revoked_at: None,
        };
        let summary = device.summary();

        next.invitations.remove(invitation_id);
        next.tombstones.insert(
            invitation_id.to_string(),
            InvitationTombstone {
                invitation_id: invitation_id.to_string(),
                consumed_at: now,
                device_id: Some(challenge.credential_id.clone()),
            },
        );
        next.devices.insert(challenge.credential_id.clone(), device);

        if let Err(error) = self.persist(&next).await {
            error!("persisting pairing grant failed: {error:#}");
            return Err(RedeemError::Unavailable);
        }
        *guard = next;
        self.record_fresh_client_nonce(&challenge.credential_id, request.client_nonce())
            .await?;
        Ok(EnrolledDevice {
            device_id: summary.device_id,
            display_name: summary.display_name,
            endpoint_fingerprint: summary.endpoint_fingerprint,
            device_key_fingerprint: summary.device_key_fingerprint,
            created_at: summary.created_at,
        })
    }

    /// Verify a fresh hardware-backed credential proof for one agent
    /// operation. No endpoint-only authorization path exists in v2.
    pub async fn authorize_operation(
        &self,
        request: &RequestV2,
        challenge: &ProofChallengeV2,
        proof: &ProofV2,
        host_endpoint_id: &str,
        authenticated_client_endpoint_id: &str,
    ) -> Result<(), RedeemError> {
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
    ) -> Result<(), RedeemError> {
        validate_challenge_proof(challenge, proof, now)?;
        let credential_id = request.credential_id().ok_or(RedeemError::Unavailable)?;
        if credential_id != challenge.credential_id {
            return Err(RedeemError::Unavailable);
        }

        let public_key = {
            let state = self.state.lock().await;
            let device = state
                .devices
                .get(credential_id)
                .filter(|device| {
                    device.revoked_at.is_none()
                        && device.endpoint_id == authenticated_client_endpoint_id
                })
                .ok_or(RedeemError::Unavailable)?;
            device.device_public_key.clone()
        };
        let (verifying_key, key_bytes) =
            parse_device_public_key(&public_key).map_err(|_| RedeemError::Unavailable)?;
        let key_hash = Sha256::digest(&key_bytes).into();
        let transcript = encode_proof_transcript(&ProofTranscript {
            host_endpoint_id,
            client_endpoint_id: authenticated_client_endpoint_id,
            operation: request.operation(),
            credential_id,
            device_key_hash: &key_hash,
            challenge_id: &challenge.challenge_id,
            server_nonce: &challenge.server_nonce,
            client_nonce: request.client_nonce(),
            operation_payload_hash: &request.operation_payload_hash(),
        })
        .map_err(|_| RedeemError::Unavailable)?;
        verify_signature(&verifying_key, &transcript, &proof.signature)?;
        self.record_fresh_client_nonce(credential_id, request.client_nonce())
            .await
    }

    async fn record_fresh_client_nonce(
        &self,
        credential_id: &str,
        client_nonce: &str,
    ) -> Result<(), RedeemError> {
        let mut replay = self.recent_client_nonces.lock().await;
        let recent = replay.entry(credential_id.to_string()).or_default();
        if recent.iter().any(|nonce| nonce == client_nonce) {
            return Err(RedeemError::Unavailable);
        }
        recent.push_back(client_nonce.to_string());
        while recent.len() > MAX_RECENT_CLIENT_NONCES {
            recent.pop_front();
        }
        Ok(())
    }

    #[cfg(test)]
    async fn redeem_at(
        &self,
        invitation_id: &str,
        secret: &str,
        authenticated_client_endpoint_id: &str,
        device_name: &str,
        now: i64,
    ) -> Result<EnrolledDevice, RedeemError> {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer;

        let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
        let public_key = signing_key.verifying_key().to_encoded_point(false);
        let device_public_key = URL_SAFE_NO_PAD.encode(public_key.as_bytes());
        let request = RequestV2::Enroll {
            v: PROTOCOL_VERSION_V2,
            invitation_id: invitation_id.to_string(),
            secret: secret.to_string(),
            device_name: device_name.to_string(),
            device_public_key,
            client_nonce: random_urlsafe(NONCE_BYTES),
        };
        let credential_id = {
            let state = self.state.lock().await;
            unique_device_id(&state)
        };
        let challenge = ProofChallengeV2::issue_at(credential_id, now);
        let key_hash = Sha256::digest(public_key.as_bytes()).into();
        let transcript = encode_proof_transcript(&ProofTranscript {
            host_endpoint_id: "host-endpoint",
            client_endpoint_id: authenticated_client_endpoint_id,
            operation: request.operation(),
            credential_id: &challenge.credential_id,
            device_key_hash: &key_hash,
            challenge_id: &challenge.challenge_id,
            server_nonce: &challenge.server_nonce,
            client_nonce: request.client_nonce(),
            operation_payload_hash: &request.operation_payload_hash(),
        })
        .map_err(|_| RedeemError::Unavailable)?;
        let signature: Signature = signing_key.sign(&transcript);
        let proof = ProofV2 {
            v: PROTOCOL_VERSION_V2,
            challenge_id: challenge.challenge_id.clone(),
            signature: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
        };
        self.redeem_with_proof_at(
            &request,
            &challenge,
            &proof,
            "host-endpoint",
            authenticated_client_endpoint_id,
            now,
        )
        .await
    }

    #[cfg(test)]
    async fn is_authorized(&self, authenticated_endpoint_id: &str) -> bool {
        let state = self.state.lock().await;
        state.devices.values().any(|device| {
            device.endpoint_id == authenticated_endpoint_id && device.revoked_at.is_none()
        })
    }

    pub async fn list_devices(&self) -> Vec<DeviceSummary> {
        let guard = self.state.lock().await;
        let mut devices: Vec<_> = guard.devices.values().map(DeviceRecord::summary).collect();
        devices.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.device_id.cmp(&right.device_id))
        });
        devices
    }

    /// Revoke one device without rotating or disrupting unrelated grants.
    /// Existing connections for the endpoint are closed after the tombstone
    /// is durable; every new stream also re-checks authorization.
    pub async fn revoke_device(&self, device_id: &str) -> anyhow::Result<Option<DeviceSummary>> {
        let now = unix_now();
        let endpoint_id = {
            let mut guard = self.state.lock().await;
            let Some(current) = guard.devices.get(device_id) else {
                return Ok(None);
            };
            if current.revoked_at.is_some() {
                return Ok(Some(current.summary()));
            }

            let mut next = guard.clone();
            let device = next
                .devices
                .get_mut(device_id)
                .expect("device existed in cloned state");
            device.revoked_at = Some(now);
            let endpoint_id = device.endpoint_id.clone();
            let summary = device.summary();
            self.persist(&next).await?;
            *guard = next;
            (endpoint_id, summary)
        };

        self.close_connections(&endpoint_id.0).await;
        Ok(Some(endpoint_id.1))
    }

    pub async fn register_connection(&self, endpoint_id: String, connection: Connection) {
        self.active
            .lock()
            .await
            .entry(endpoint_id)
            .or_default()
            .push(connection);
    }

    pub async fn unregister_connection(&self, endpoint_id: &str, stable_id: usize) {
        let mut active = self.active.lock().await;
        if let Some(connections) = active.get_mut(endpoint_id) {
            connections.retain(|connection| connection.stable_id() != stable_id);
            if connections.is_empty() {
                active.remove(endpoint_id);
            }
        }
    }

    async fn close_connections(&self, endpoint_id: &str) {
        let connections = self
            .active
            .lock()
            .await
            .remove(endpoint_id)
            .unwrap_or_default();
        for connection in connections {
            connection.close(VarInt::from_u32(0x21), b"device revoked");
        }
    }

    async fn persist(&self, state: &PersistedState) -> anyhow::Result<()> {
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
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            invitations: BTreeMap::new(),
            devices: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct InvitationRecord {
    invitation_id: String,
    secret_hash: String,
    created_at: i64,
    expires_at: i64,
}

#[derive(Clone, Serialize, Deserialize)]
struct DeviceRecord {
    device_id: String,
    endpoint_id: String,
    device_public_key: String,
    display_name: String,
    created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revoked_at: Option<i64>,
}

impl DeviceRecord {
    fn summary(&self) -> DeviceSummary {
        DeviceSummary {
            device_id: self.device_id.clone(),
            display_name: self.display_name.clone(),
            endpoint_fingerprint: endpoint_fingerprint(&self.endpoint_id),
            device_key_fingerprint: device_key_fingerprint(&self.device_public_key),
            created_at: self.created_at,
            revoked_at: self.revoked_at,
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

fn sweep_expired(state: &mut PersistedState, now: i64) {
    let expired: Vec<_> = state
        .invitations
        .values()
        .filter(|record| record.expires_at <= now)
        .map(|record| record.invitation_id.clone())
        .collect();
    for invitation_id in expired {
        expire_invitation(state, &invitation_id, now);
    }
    state
        .tombstones
        .retain(|_, tombstone| tombstone.consumed_at > now - TOMBSTONE_RETENTION_SECS);
}

fn expire_invitation(state: &mut PersistedState, invitation_id: &str, now: i64) {
    if state.invitations.remove(invitation_id).is_some() {
        state.tombstones.insert(
            invitation_id.to_string(),
            InvitationTombstone {
                invitation_id: invitation_id.to_string(),
                consumed_at: now,
                device_id: None,
            },
        );
    }
}

fn unique_random_id(state: &PersistedState, bytes: usize) -> String {
    loop {
        let candidate = random_urlsafe(bytes);
        if !state.invitations.contains_key(&candidate) && !state.tombstones.contains_key(&candidate)
        {
            return candidate;
        }
    }
}

fn unique_device_id(state: &PersistedState) -> String {
    loop {
        let candidate = random_urlsafe(DEVICE_ID_BYTES);
        if !state.devices.contains_key(&candidate) {
            return candidate;
        }
    }
}

fn random_urlsafe(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn valid_invitation_id(value: &str) -> bool {
    value.len() == 22
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn valid_opaque_id(value: &str) -> bool {
    value.len() == 22
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn invitation_secret_hash(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SECRET_HASH_DOMAIN);
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

fn secret_hash_matches(expected_hex: &str, candidate_secret: &str) -> bool {
    let Ok(expected) = hex::decode(expected_hex) else {
        return false;
    };
    let actual = invitation_secret_hash(candidate_secret);
    expected.len() == actual.len() && bool::from(expected.as_slice().ct_eq(actual.as_slice()))
}

fn endpoint_fingerprint(endpoint_id: &str) -> String {
    let digest = Sha256::digest(endpoint_id.as_bytes());
    hex::encode(&digest[..8])
}

fn device_key_fingerprint(device_public_key: &str) -> String {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(device_public_key) else {
        return "invalid".to_string();
    };
    let digest = Sha256::digest(bytes);
    hex::encode(&digest[..8])
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
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    decoded.try_into().ok()
}

fn validate_challenge_proof(
    challenge: &ProofChallengeV2,
    proof: &ProofV2,
    now: i64,
) -> Result<(), RedeemError> {
    if proof.v != PROTOCOL_VERSION_V2
        || proof.challenge_id != challenge.challenge_id
        || challenge.expires_at <= now
        || !valid_opaque_id(&challenge.challenge_id)
        || !valid_opaque_id(&challenge.credential_id)
        || decode_nonce(&challenge.server_nonce).is_none()
    {
        return Err(RedeemError::Unavailable);
    }
    Ok(())
}

fn verify_signature(
    verifying_key: &VerifyingKey,
    transcript: &[u8],
    signature: &str,
) -> Result<(), RedeemError> {
    if signature.len() > 128 {
        return Err(RedeemError::Unavailable);
    }
    let der = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| RedeemError::Unavailable)?;
    let signature = Signature::from_der(&der).map_err(|_| RedeemError::Unavailable)?;
    verifying_key
        .verify(transcript, &signature)
        .map_err(|_| RedeemError::Unavailable)
}

/// Exact inputs to the v2 proof transcript. All string fields are UTF-8 and
/// length-prefixed by a four-byte unsigned big-endian length. Hash/nonce
/// fields are appended as their fixed 32 raw bytes.
pub struct ProofTranscript<'a> {
    pub host_endpoint_id: &'a str,
    pub client_endpoint_id: &'a str,
    pub operation: &'a str,
    pub credential_id: &'a str,
    pub device_key_hash: &'a [u8; 32],
    pub challenge_id: &'a str,
    pub server_nonce: &'a str,
    pub client_nonce: &'a str,
    pub operation_payload_hash: &'a [u8; 32],
}

/// Canonical P-256 signing message for Remora Link v2.
///
/// Field order is fixed:
/// domain, host Iroh id, client Iroh id, operation, credential id,
/// device-key hash, challenge id, server nonce, client nonce, payload hash.
pub fn encode_proof_transcript(input: &ProofTranscript<'_>) -> anyhow::Result<Vec<u8>> {
    let server_nonce = decode_nonce(input.server_nonce)
        .ok_or_else(|| anyhow!("server nonce must decode to 32 bytes"))?;
    let client_nonce = decode_nonce(input.client_nonce)
        .ok_or_else(|| anyhow!("client nonce must decode to 32 bytes"))?;
    let mut transcript = Vec::with_capacity(256);
    append_field(&mut transcript, PROOF_TRANSCRIPT_DOMAIN)?;
    append_field(&mut transcript, input.host_endpoint_id.as_bytes())?;
    append_field(&mut transcript, input.client_endpoint_id.as_bytes())?;
    append_field(&mut transcript, input.operation.as_bytes())?;
    append_field(&mut transcript, input.credential_id.as_bytes())?;
    transcript.extend_from_slice(input.device_key_hash);
    append_field(&mut transcript, input.challenge_id.as_bytes())?;
    transcript.extend_from_slice(&server_nonce);
    transcript.extend_from_slice(&client_nonce);
    transcript.extend_from_slice(input.operation_payload_hash);
    Ok(transcript)
}

fn hash_operation_payload(fields: &[&str]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(128);
    append_field(&mut payload, OPERATION_PAYLOAD_DOMAIN).expect("static domain fits u32");
    for field in fields {
        append_field(&mut payload, field.as_bytes()).expect("Rust string length fits u32");
    }
    Sha256::digest(payload).into()
}

fn append_field(target: &mut Vec<u8>, field: &[u8]) -> anyhow::Result<()> {
    let length: u32 = field
        .len()
        .try_into()
        .map_err(|_| anyhow!("transcript field is too large"))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(field);
    Ok(())
}

fn normalize_device_name(value: &str) -> String {
    let normalized: String = value
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(80)
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

async fn atomic_write(target: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| anyhow!("pairing store has no parent: {}", target.display()))?;
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("creating {}", parent.display()))?;
    // Open the directory before the rename so all setup that can fail does so
    // before the commit point. The post-rename sync is still attempted and
    // reported, but the rename is treated as committed so callers advance
    // their in-memory state instead of diverging from the file on disk.
    let parent_directory = open_parent_directory(parent).await?;

    let mut suffix = [0_u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let temporary = target.with_extension(format!("tmp-{}", hex::encode(suffix)));
    let write_result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .await
            .with_context(|| format!("opening {}", temporary.display()))?;
        // Establish owner-only permissions before writing any credential
        // material. The parent is also 0700 on Unix, but the file should be
        // safe independently of that invariant.
        set_mode_0600(&temporary)?;
        file.write_all(contents)
            .await
            .with_context(|| format!("writing {}", temporary.display()))?;
        file.flush().await?;
        file.sync_all().await?;
        tokio::fs::rename(&temporary, target)
            .await
            .with_context(|| format!("renaming {} -> {}", temporary.display(), target.display()))?;
        if let Err(sync_error) = sync_parent_directory(&parent_directory, parent).await {
            error!(
                path = %parent.display(),
                "pairing-store rename committed but directory sync failed: {sync_error:#}"
            );
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;

    if write_result.is_err()
        && let Err(cleanup_error) = tokio::fs::remove_file(&temporary).await
        && cleanup_error.kind() != std::io::ErrorKind::NotFound
    {
        warn!(path = %temporary.display(), "failed to remove pairing-store temporary file");
    }
    write_result
}

/// Make the rename itself crash-durable. File contents are synced before the
/// rename; syncing the containing directory persists the new directory entry
/// (including invitation consumption and revocation tombstones).
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

    async fn manager() -> (tempfile::TempDir, PairingManager) {
        let temp = tempfile::tempdir().unwrap();
        let manager = PairingManager::load(temp.path().join("pairing-v2.json"))
            .await
            .unwrap();
        (temp, manager)
    }

    async fn invitation(manager: &PairingManager, now: i64) -> PairingInvitation {
        manager
            .create_invitation_at(
                "host-endpoint".to_string(),
                Some("Development Mac".to_string()),
                Some("https://relay.example".to_string()),
                now,
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn invitation_is_high_entropy_short_lived_and_secret_is_redacted() {
        let (_temp, manager) = manager().await;
        let invite = invitation(&manager, 1_000).await;
        assert_eq!(invite.v, PROTOCOL_VERSION_V2);
        assert_eq!(invite.expires_at, 1_300);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&invite.invitation_id).unwrap().len(),
            16
        );
        assert_eq!(URL_SAFE_NO_PAD.decode(&invite.secret).unwrap().len(), 32);
        let rendered = format!("{invite:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&invite.secret));

        let disk = tokio::fs::read_to_string(&manager.path).await.unwrap();
        assert!(!disk.contains(&invite.secret));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&manager.path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        let live_invite = manager
            .create_invitation(
                iroh::SecretKey::generate().public().to_string(),
                Some("Development Mac".to_string()),
                Some("https://relay.example".to_string()),
            )
            .await
            .unwrap();
        let code = live_invite.to_pairing_code().unwrap();
        assert!(code.starts_with(PAIRING_CODE_PREFIX));
        assert_eq!(
            PairingInvitation::from_pairing_code(&code).unwrap(),
            live_invite
        );
    }

    #[tokio::test]
    async fn redeem_binds_authenticated_endpoint_and_survives_reload() {
        let (temp, manager) = manager().await;
        let invite = invitation(&manager, 1_000).await;
        let grant = manager
            .redeem_at(
                &invite.invitation_id,
                &invite.secret,
                "authenticated-client-endpoint",
                "  Aman's iPhone\n",
                1_001,
            )
            .await
            .unwrap();

        assert_eq!(grant.display_name, "Aman's iPhone");
        assert!(manager.is_authorized("authenticated-client-endpoint").await);
        assert!(!manager.is_authorized("request-supplied-endpoint").await);

        let reloaded = PairingManager::load(temp.path().join("pairing-v2.json"))
            .await
            .unwrap();
        assert!(
            reloaded
                .is_authorized("authenticated-client-endpoint")
                .await
        );
        let devices = reloaded.list_devices().await;
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, grant.device_id);
        assert!(
            !serde_json::to_string(&devices)
                .unwrap()
                .contains("authenticated-client-endpoint")
        );
    }

    #[tokio::test]
    async fn concurrent_redemption_has_exactly_one_winner() {
        let (_temp, manager) = manager().await;
        let invite = invitation(&manager, 1_000).await;
        let left_manager = manager.clone();
        let right_manager = manager.clone();
        let left_id = invite.invitation_id.clone();
        let right_id = invite.invitation_id.clone();
        let left_secret = invite.secret.clone();
        let right_secret = invite.secret.clone();

        let (left, right) = tokio::join!(
            left_manager.redeem_at(&left_id, &left_secret, "endpoint-a", "A", 1_001),
            right_manager.redeem_at(&right_id, &right_secret, "endpoint-b", "B", 1_001),
        );
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        assert_eq!(manager.list_devices().await.len(), 1);
    }

    #[tokio::test]
    async fn consumed_invitation_cannot_be_replayed_by_same_or_other_endpoint() {
        let (_temp, manager) = manager().await;
        let invite = invitation(&manager, 1_000).await;
        manager
            .redeem_at(
                &invite.invitation_id,
                &invite.secret,
                "endpoint-a",
                "A",
                1_001,
            )
            .await
            .unwrap();

        for endpoint in ["endpoint-a", "endpoint-b"] {
            assert_eq!(
                manager
                    .redeem_at(
                        &invite.invitation_id,
                        &invite.secret,
                        endpoint,
                        "Replay",
                        1_002,
                    )
                    .await,
                Err(RedeemError::Unavailable)
            );
        }
    }

    #[tokio::test]
    async fn malformed_wrong_expired_and_replayed_errors_are_indistinguishable() {
        let (_temp, manager) = manager().await;
        let invite = invitation(&manager, 1_000).await;
        let wrong = manager
            .redeem_at(&invite.invitation_id, "wrong", "endpoint-a", "A", 1_001)
            .await;
        let malformed = manager
            .redeem_at("not-an-id", &invite.secret, "endpoint-a", "A", 1_001)
            .await;
        let expired = manager
            .redeem_at(
                &invite.invitation_id,
                &invite.secret,
                "endpoint-a",
                "A",
                1_301,
            )
            .await;
        assert_eq!(wrong, Err(RedeemError::Unavailable));
        assert_eq!(malformed, Err(RedeemError::Unavailable));
        assert_eq!(expired, Err(RedeemError::Unavailable));
        assert_eq!(
            wrong.unwrap_err().to_string(),
            expired.unwrap_err().to_string()
        );
    }

    #[tokio::test]
    async fn selective_revocation_is_durable_and_endpoint_cannot_reenroll() {
        let (temp, manager) = manager().await;
        let first = invitation(&manager, 1_000).await;
        let first_grant = manager
            .redeem_at(
                &first.invitation_id,
                &first.secret,
                "endpoint-a",
                "A",
                1_001,
            )
            .await
            .unwrap();
        let second = invitation(&manager, 1_002).await;
        manager
            .redeem_at(
                &second.invitation_id,
                &second.secret,
                "endpoint-b",
                "B",
                1_003,
            )
            .await
            .unwrap();

        let revoked = manager
            .revoke_device(&first_grant.device_id)
            .await
            .unwrap()
            .unwrap();
        assert!(revoked.revoked_at.is_some());
        assert!(!manager.is_authorized("endpoint-a").await);
        assert!(manager.is_authorized("endpoint-b").await);

        let retry = invitation(&manager, 1_004).await;
        assert_eq!(
            manager
                .redeem_at(
                    &retry.invitation_id,
                    &retry.secret,
                    "endpoint-a",
                    "A2",
                    1_005
                )
                .await,
            Err(RedeemError::Unavailable)
        );

        let reloaded = PairingManager::load(temp.path().join("pairing-v2.json"))
            .await
            .unwrap();
        assert!(!reloaded.is_authorized("endpoint-a").await);
        assert!(reloaded.is_authorized("endpoint-b").await);
    }

    #[test]
    fn v2_request_debug_redacts_enrollment_secret() {
        let request = RequestV2::Enroll {
            v: 2,
            invitation_id: "abcdefghijklmnopqrstuv".to_string(),
            secret: "top-secret-value".to_string(),
            device_name: "Phone".to_string(),
            device_public_key: "public-key".to_string(),
            client_nonce: "client-nonce".to_string(),
        };
        let rendered = format!("{request:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("top-secret-value"));
    }

    #[test]
    fn v1_token_is_rejected_as_unknown_v2_field() {
        let v1 = r#"{"op":"list_agents","v":1,"token":"legacy-token"}"#;
        assert!(serde_json::from_str::<RequestV2>(v1).is_err());
    }

    fn signing_key_and_public() -> (p256::ecdsa::SigningKey, String) {
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let public = signing_key.verifying_key().to_encoded_point(false);
        (signing_key, URL_SAFE_NO_PAD.encode(public.as_bytes()))
    }

    fn sign_request(
        request: &RequestV2,
        challenge: &ProofChallengeV2,
        signing_key: &p256::ecdsa::SigningKey,
        host_endpoint_id: &str,
        client_endpoint_id: &str,
    ) -> ProofV2 {
        use p256::ecdsa::signature::Signer;

        let public = signing_key.verifying_key().to_encoded_point(false);
        let device_key_hash = Sha256::digest(public.as_bytes()).into();
        let transcript = encode_proof_transcript(&ProofTranscript {
            host_endpoint_id,
            client_endpoint_id,
            operation: request.operation(),
            credential_id: &challenge.credential_id,
            device_key_hash: &device_key_hash,
            challenge_id: &challenge.challenge_id,
            server_nonce: &challenge.server_nonce,
            client_nonce: request.client_nonce(),
            operation_payload_hash: &request.operation_payload_hash(),
        })
        .unwrap();
        let signature: Signature = signing_key.sign(&transcript);
        ProofV2 {
            v: PROTOCOL_VERSION_V2,
            challenge_id: challenge.challenge_id.clone(),
            signature: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
        }
    }

    async fn enroll_with_key(
        manager: &PairingManager,
        invite: &PairingInvitation,
        endpoint_id: &str,
        now: i64,
    ) -> (EnrolledDevice, p256::ecdsa::SigningKey) {
        let (signing_key, device_public_key) = signing_key_and_public();
        let request = RequestV2::Enroll {
            v: PROTOCOL_VERSION_V2,
            invitation_id: invite.invitation_id.clone(),
            secret: invite.secret.clone(),
            device_name: "Test phone".to_string(),
            device_public_key,
            client_nonce: random_urlsafe(NONCE_BYTES),
        };
        let credential_id = {
            let state = manager.state.lock().await;
            unique_device_id(&state)
        };
        let challenge = ProofChallengeV2::issue_at(credential_id, now);
        let proof = sign_request(
            &request,
            &challenge,
            &signing_key,
            "host-endpoint",
            endpoint_id,
        );
        let enrolled = manager
            .redeem_with_proof_at(
                &request,
                &challenge,
                &proof,
                "host-endpoint",
                endpoint_id,
                now,
            )
            .await
            .unwrap();
        (enrolled, signing_key)
    }

    #[tokio::test]
    async fn endpoint_allowlist_without_device_proof_fails_closed() {
        let (_temp, manager) = manager().await;
        let invite = invitation(&manager, 1_000).await;
        let (enrolled, _signing_key) =
            enroll_with_key(&manager, &invite, "client-endpoint", 1_001).await;
        let request = RequestV2::ListAgents {
            v: PROTOCOL_VERSION_V2,
            credential_id: enrolled.device_id.clone(),
            client_nonce: random_urlsafe(NONCE_BYTES),
        };
        let challenge = ProofChallengeV2::issue_at(enrolled.device_id, 1_002);
        let bogus = ProofV2 {
            v: PROTOCOL_VERSION_V2,
            challenge_id: challenge.challenge_id.clone(),
            signature: URL_SAFE_NO_PAD.encode([0_u8; 64]),
        };
        assert_eq!(
            manager
                .authorize_operation_at(
                    &request,
                    &challenge,
                    &bogus,
                    "host-endpoint",
                    "client-endpoint",
                    1_003,
                )
                .await,
            Err(RedeemError::Unavailable)
        );
    }

    #[tokio::test]
    async fn proof_is_bound_to_endpoint_operation_and_fresh_client_nonce() {
        let (_temp, manager) = manager().await;
        let invite = invitation(&manager, 1_000).await;
        let (enrolled, signing_key) =
            enroll_with_key(&manager, &invite, "client-endpoint", 1_001).await;
        let request = RequestV2::RestartAgent {
            v: PROTOCOL_VERSION_V2,
            credential_id: enrolled.device_id.clone(),
            client_nonce: random_urlsafe(NONCE_BYTES),
            agent: "codex".to_string(),
        };
        let challenge = ProofChallengeV2::issue_at(enrolled.device_id, 1_002);
        let proof = sign_request(
            &request,
            &challenge,
            &signing_key,
            "host-endpoint",
            "client-endpoint",
        );

        assert_eq!(
            manager
                .authorize_operation_at(
                    &request,
                    &challenge,
                    &proof,
                    "host-endpoint",
                    "other-endpoint",
                    1_003,
                )
                .await,
            Err(RedeemError::Unavailable)
        );
        manager
            .authorize_operation_at(
                &request,
                &challenge,
                &proof,
                "host-endpoint",
                "client-endpoint",
                1_003,
            )
            .await
            .unwrap();
        assert_eq!(
            manager
                .authorize_operation_at(
                    &request,
                    &challenge,
                    &proof,
                    "host-endpoint",
                    "client-endpoint",
                    1_003,
                )
                .await,
            Err(RedeemError::Unavailable)
        );

        let tampered = RequestV2::RestartAgent {
            v: PROTOCOL_VERSION_V2,
            credential_id: challenge.credential_id.clone(),
            client_nonce: random_urlsafe(NONCE_BYTES),
            agent: "claude".to_string(),
        };
        assert_eq!(
            manager
                .authorize_operation_at(
                    &tampered,
                    &challenge,
                    &proof,
                    "host-endpoint",
                    "client-endpoint",
                    1_003,
                )
                .await,
            Err(RedeemError::Unavailable)
        );
    }

    #[test]
    fn proof_transcript_golden_vector() {
        let device_key_hash = std::array::from_fn(|index| index as u8);
        let payload_hash = [0x33_u8; 32];
        let server_nonce = URL_SAFE_NO_PAD.encode([0x11_u8; 32]);
        let client_nonce = URL_SAFE_NO_PAD.encode([0x22_u8; 32]);
        let transcript = encode_proof_transcript(&ProofTranscript {
            host_endpoint_id: "host-123",
            client_endpoint_id: "client-456",
            operation: "list_agents",
            credential_id: "credential-789",
            device_key_hash: &device_key_hash,
            challenge_id: "challenge-abc",
            server_nonce: &server_nonce,
            client_nonce: &client_nonce,
            operation_payload_hash: &payload_hash,
        })
        .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(transcript)),
            "f0c10b40b3150710335fae693c64be5d435b7dd9d1f8642bff9df0f60929909b"
        );
    }
}
