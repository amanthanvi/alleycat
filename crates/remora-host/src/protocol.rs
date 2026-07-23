use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentWire {
    Websocket,
    Jsonl,
}

impl AgentWire {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Websocket => "websocket",
            Self::Jsonl => "jsonl",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentInfo {
    pub name: String,
    pub display_name: String,
    pub wire: AgentWire,
    pub available: bool,
    /// UI-facing presentation hints. Optional so older remora daemons
    /// continue to round-trip without this field; new clients render
    /// generic fallbacks when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation: Option<AgentPresentation>,
    /// Behavioral capability flags that let clients branch on
    /// agent-specific behavior (reasoning-effort lock, visible mode
    /// allowlist, transport eligibility) without hardcoding agent names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<AgentCapabilities>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AgentPresentation {
    /// Longer/formal title used in headers, e.g. "Factory Droid" while
    /// `display_name` is "Droid". Falls back to `display_name` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Whether the BETA badge should be shown next to this agent.
    #[serde(default)]
    pub is_beta: bool,
    /// Ascending sort key. Ties broken by `name`.
    #[serde(default)]
    pub sort_order: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Alternate lowercase names that should also resolve to this agent
    /// (back-compat for clients that persisted a different alias).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AgentCapabilities {
    /// Amp behavior: reasoning effort is locked once the thread has any
    /// activity. Clients hide / disable the effort selector when true.
    #[serde(default)]
    pub locks_reasoning_effort_after_activity: bool,
    /// Allowlist of mode names the model selector should show. `None`
    /// means no filtering; show all modes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visible_modes: Option<Vec<String>>,
    /// Agent can be reached via the SSH bridge bootstrap path
    /// (Claude / Pi / Opencode / Codex today).
    #[serde(default)]
    pub supports_ssh_bridge: bool,
    /// Codex-only: the agent speaks the `codex app-server` wire and can
    /// be dialed directly on its TCP port without going through Remora.
    #[serde(default)]
    pub uses_direct_codex_port: bool,
    /// Whether a client may send per-thread approval/sandbox overrides and
    /// expect the runtime to enforce them. False for bridges that launch in a
    /// fixed/yolo-like mode or whose upstream agent has no thread permission
    /// profile system.
    #[serde(default)]
    pub supports_thread_permission_overrides: bool,
    /// Whether thread snapshots from this agent contain authoritative
    /// effective approval/sandbox policies. False means clients should not
    /// hydrate or imply permissions from missing/placeholder values.
    #[serde(default)]
    pub reports_effective_thread_permissions: bool,
}

/// What `Connect` resolved to on the server side.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttachKind {
    /// No prior session existed; one was minted for this client.
    Fresh,
    /// Prior session reattached and the resume cursor was within the replay
    /// window. The drainer will replay missed frames before going live.
    Resumed,
    /// Prior session existed but the cursor predates the ring floor. The
    /// client must reload state from authoritative storage (e.g. `thread/read`)
    /// before treating this stream as caught up; backlog replay is empty.
    DriftReload,
}

impl From<remora_bridge_core::session::AttachKind> for AttachKind {
    fn from(value: remora_bridge_core::session::AttachKind) -> Self {
        match value {
            remora_bridge_core::session::AttachKind::Fresh => Self::Fresh,
            remora_bridge_core::session::AttachKind::Resumed => Self::Resumed,
            remora_bridge_core::session::AttachKind::DriftReload => Self::DriftReload,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionInfo {
    pub attached: AttachKind,
    pub current_seq: u64,
    pub floor_seq: u64,
}
