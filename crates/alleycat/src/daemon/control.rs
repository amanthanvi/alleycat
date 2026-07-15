//! Control protocol types exchanged over the IPC stream between the CLI and
//! the daemon. One request per connection, one response, then close. The
//! wire frame is a length-prefixed JSON envelope provided by
//! `crate::framing::{read_json_frame, write_json_frame}`.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::pairing_v2::{DeviceSummary, PairingInvitation};
use crate::protocol::{AgentInfo, PairPayload};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Aggregate status: pid, node id, token fingerprint, agent availability.
    Status,
    /// Mint a one-time, short-lived Remora Link v2 invitation with an exact
    /// maximum runtime allowlist and closed scope ceiling.
    Pair {
        runtime_ids: Vec<String>,
        allow_restart: bool,
        unattended: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl_secs: Option<u64>,
    },
    /// Emit the legacy host-global v1 bearer. Compatibility escape hatch
    /// only; it can never create or upgrade a v2 device grant.
    PairLegacy,
    /// Mint a fresh token. Node id is preserved.
    Rotate,
    /// Re-read host.toml and swap agent config.
    Reload,
    /// Graceful shutdown.
    Stop,
    /// Agent introspection.
    AgentsList,
    /// Redacted, stable device-grant summaries.
    DevicesList,
    /// Selectively revoke one v2 device grant.
    DeviceRevoke { device_id: String },
    /// Redacted pending enrollment claims awaiting local host confirmation.
    PairingsPending,
    /// Approve one pending claim, optionally narrowing its runtime and scope
    /// request. Self-revocation remains implicit and cannot be removed.
    PairingApprove {
        claim_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        runtime_ids: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scopes: Option<Vec<PairingApprovalScope>>,
    },
    /// Reject one pending enrollment claim. Repeating a rejection is safe.
    PairingReject { claim_id: String },
}

impl Request {
    /// A non-sensitive label for routine diagnostics. The request's derived
    /// `Debug` representation may contain stable grant or claim identifiers.
    pub(crate) fn operation_name(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Pair { .. } => "pair",
            Self::PairLegacy => "pair_legacy",
            Self::Rotate => "rotate",
            Self::Reload => "reload",
            Self::Stop => "stop",
            Self::AgentsList => "agents_list",
            Self::DevicesList => "devices_list",
            Self::DeviceRevoke { .. } => "device_revoke",
            Self::PairingsPending => "pairings_pending",
            Self::PairingApprove { .. } => "pairing_approve",
            Self::PairingReject { .. } => "pairing_reject",
        }
    }
}

/// Host-selectable runtime authority. Self-revocation is deliberately absent:
/// the daemon adds it to every invitation and grant.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "snake_case")]
pub enum PairingApprovalScope {
    Inspect,
    Connect,
    Restart,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl Response {
    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
            data: None,
        }
    }

    pub fn ok_with<T: Serialize>(data: &T) -> anyhow::Result<Self> {
        Ok(Self {
            ok: true,
            error: None,
            data: Some(serde_json::to_value(data)?),
        })
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            data: None,
        }
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        if let Some(error) = self.error.as_mut() {
            error.zeroize();
        }
        if let Some(data) = self.data.as_mut() {
            zeroize_json_value(data);
        }
    }
}

fn zeroize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(value) => value.zeroize(),
        serde_json::Value::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                zeroize_json_value(value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub pid: u32,
    pub node_id: String,
    pub token_short: String,
    pub relay: Option<String>,
    pub config_path: String,
    pub uptime_secs: u64,
    pub agents: Vec<AgentInfo>,
    /// SemVer of the *binary* that's currently running the daemon (e.g.
    /// `kittylitter 0.2.1`). The CLI compares this against its own version
    /// to detect a stale daemon and offer a transparent restart. Optional
    /// for forwards compatibility with daemons that predate the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateResult {
    pub token_short: String,
    pub payload: PairPayload,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PairingResultV2 {
    pub invitation: PairingInvitation,
    pub code: String,
}

impl std::fmt::Debug for PairingResultV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingResultV2")
            .field("invitation", &self.invitation)
            .field("code", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PairingResultV2 {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRevokeResult {
    pub device: DeviceSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingApprovalResult {
    pub device: DeviceSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRejectionResult {
    pub claim_id: String,
    pub rejected: bool,
}

/// First 16 hex chars of SHA-256(token).
pub fn token_fingerprint(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(&digest[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_request_serializes_with_op_tag() {
        let r = Request::Status;
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"op":"status"}"#);
    }

    #[test]
    fn rotate_request_round_trips() {
        let s = serde_json::to_string(&Request::Rotate).unwrap();
        let back: Request = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Request::Rotate));
    }

    #[test]
    fn device_revoke_request_round_trips() {
        let request = Request::DeviceRevoke {
            device_id: "device-1".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        let decoded: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Request::DeviceRevoke { device_id } if device_id == "device-1"
        ));
    }

    #[test]
    fn scoped_pair_request_round_trips() {
        let request = Request::Pair {
            runtime_ids: vec!["codex".to_string()],
            allow_restart: false,
            unattended: false,
            ttl_secs: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains(r#""op":"pair""#));
        assert!(json.contains(r#""runtime_ids":["codex"]"#));
        assert!(!json.contains("ttl_secs"));
        let decoded: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Request::Pair {
                runtime_ids,
                allow_restart: false,
                unattended: false,
                ttl_secs: None,
            } if runtime_ids == ["codex"]
        ));
    }

    #[test]
    fn pairing_approve_request_has_closed_scopes() {
        let request = Request::PairingApprove {
            claim_id: "claim-1".to_string(),
            runtime_ids: Some(vec!["codex".to_string()]),
            scopes: Some(vec![
                PairingApprovalScope::Inspect,
                PairingApprovalScope::Connect,
            ]),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            json,
            r#"{"op":"pairing_approve","claim_id":"claim-1","runtime_ids":["codex"],"scopes":["inspect","connect"]}"#
        );
        let decoded: Request = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(decoded, Request::PairingApprove { claim_id, .. } if claim_id == "claim-1")
        );
    }

    #[test]
    fn pairing_approval_result_uses_canonical_device_summary() {
        let result = PairingApprovalResult {
            device: DeviceSummary {
                device_id: "device-1".to_string(),
                display_name: "Phone".to_string(),
                endpoint_fingerprint: "endpoint".to_string(),
                device_key_fingerprint: "key".to_string(),
                selected_runtime_ids: vec!["codex".to_string()],
                granted_scopes: vec![
                    crate::pairing_v2::DeviceScopeV2::ConnectRuntime,
                    crate::pairing_v2::DeviceScopeV2::SelfRevoke,
                ],
                auth_epoch: 0,
                state: crate::pairing_v2::GrantStateV2::Active,
                created_at: 1,
                revoked_at: None,
            },
        };
        let json = serde_json::to_value(result).unwrap();
        assert_eq!(json["device"]["state"], "active");
        assert_eq!(json["device"]["selected_runtime_ids"][0], "codex");
        assert_eq!(json["device"]["granted_scopes"][0], "connect_runtime");
        assert_eq!(json["device"]["auth_epoch"], 0);
    }

    #[test]
    fn control_requests_reject_unknown_fields() {
        let error = serde_json::from_str::<Request>(
            r#"{"op":"pair","runtime_ids":["codex"],"allow_restart":false,"unattended":false,"unexpected":true}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn response_ok_skips_optionals() {
        let r = Response::ok();
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"ok":true}"#);
    }

    #[test]
    fn response_err_includes_error() {
        let s = serde_json::to_string(&Response::err("boom")).unwrap();
        assert!(s.contains(r#""ok":false"#));
        assert!(s.contains(r#""error":"boom""#));
    }

    #[test]
    fn secret_bearing_response_values_are_recursively_zeroized() {
        let mut value = serde_json::json!({
            "invitation": { "secret": "raw-secret" },
            "code": "remora-link://v2/encoded-secret",
            "nested": ["copy-one", { "copy": "copy-two" }]
        });
        zeroize_json_value(&mut value);

        assert_eq!(value["invitation"]["secret"], "");
        assert_eq!(value["code"], "");
        assert_eq!(value["nested"][0], "");
        assert_eq!(value["nested"][1]["copy"], "");
    }

    #[test]
    fn token_fingerprint_is_16_hex() {
        let f = token_fingerprint("deadbeef");
        assert_eq!(f.len(), 16);
        assert!(f.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
