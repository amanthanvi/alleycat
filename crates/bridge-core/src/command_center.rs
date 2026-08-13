//! Durable Remora command-center domain records.
//!
//! These types are provider-neutral and Host-owned. They intentionally avoid
//! paths, provider names, and display labels as identity.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const COMMAND_CENTER_SCHEMA_VERSION: u32 = 1;
pub const OPAQUE_ID_LENGTH: usize = 22;
pub const MAX_DISPLAY_LABEL_BYTES: usize = 256;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_PROJECTS: usize = 250;
pub const MAX_WORKING_COPIES: usize = 20_000;
pub const MAX_THREADS: usize = 20_000;
pub const MAX_TURNS: usize = 200_000;
pub const MAX_PROVIDER_SESSIONS: usize = MAX_THREADS;
pub const MAX_CHECKPOINTS: usize = MAX_TURNS;
pub const MAX_PROVIDER_INSTANCES: usize = 64;
pub const MAX_MODELS_PER_PROVIDER: usize = 256;
pub const MAX_ROUTE_HANDLES: usize = MAX_THREADS;
pub const MAX_TRUSTED_SCRIPTS: usize = 1_024;
pub const MAX_BROWSER_PROFILES: usize = MAX_PROJECTS;
pub const MAX_WORK_INTENTS: usize = MAX_THREADS + MAX_TURNS;
pub const MAX_WORK_INTENT_ID_BYTES: usize = 128;
pub const MAX_COMMAND_ARGUMENTS: usize = 64;
pub const MAX_DECLARED_ENVIRONMENT: usize = 128;
pub const MAX_COMMAND_CENTER_STATUS_BYTES: usize = 512 * 1024;

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

opaque_id!(HostId);
opaque_id!(ProjectId);
opaque_id!(WorkingCopyId);
opaque_id!(ThreadId);
opaque_id!(TurnId);
opaque_id!(ProviderInstanceId);
opaque_id!(ProviderSessionId);
opaque_id!(CheckpointId);
opaque_id!(ReviewNoteId);
opaque_id!(RouteHandle);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkIntentKind {
    CreateThread,
    SendMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkIntentState {
    Reserved,
    Dispatching,
    Succeeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityState {
    Available,
    Unknown,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureAvailability {
    pub state: AvailabilityState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl FeatureAvailability {
    pub fn available() -> Self {
        Self {
            state: AvailabilityState::Available,
            reason: None,
        }
    }

    pub fn unknown(reason: impl Into<String>) -> Self {
        Self {
            state: AvailabilityState::Unknown,
            reason: Some(bound_utf8(reason.into(), MAX_DISPLAY_LABEL_BYTES)),
        }
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            state: AvailabilityState::Unavailable,
            reason: Some(bound_utf8(reason.into(), MAX_DISPLAY_LABEL_BYTES)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderReadiness {
    Ready,
    AuthenticationRequired,
    InstallationRequired,
    ConfigurationRequired,
    Starting,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelDescriptor {
    pub model_id: String,
    pub display_name: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadLifecycleCapabilitiesV1 {
    pub create: FeatureAvailability,
    pub resume: FeatureAvailability,
    pub linked_child: FeatureAvailability,
    pub archive: FeatureAvailability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnCapabilitiesV1 {
    pub text: FeatureAvailability,
    pub images: FeatureAvailability,
    pub file_references: FeatureAvailability,
    pub interrupt: FeatureAvailability,
    pub queued_follow_up: FeatureAvailability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InteractionCapabilitiesV1 {
    pub approvals: FeatureAvailability,
    pub structured_input: FeatureAvailability,
    pub ask_question: FeatureAvailability,
    pub plans: FeatureAvailability,
    pub todos: FeatureAvailability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCapabilitiesV1 {
    pub list: FeatureAvailability,
    pub select_before_first_send: FeatureAvailability,
    pub reasoning_configuration: FeatureAvailability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionCapabilitiesV1 {
    pub sandbox_modes: FeatureAvailability,
    pub declared_controls: FeatureAvailability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryCapabilitiesV1 {
    pub pagination: FeatureAvailability,
    pub hydration: FeatureAvailability,
    pub context_window_metrics: FeatureAvailability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceCapabilitiesV1 {
    pub realtime_voice: FeatureAvailability,
    pub transcript_handoff: FeatureAvailability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCapabilitiesV1 {
    pub version: u32,
    pub thread_lifecycle: ThreadLifecycleCapabilitiesV1,
    pub turns: TurnCapabilitiesV1,
    pub interaction: InteractionCapabilitiesV1,
    pub models: ModelCapabilitiesV1,
    pub permissions: PermissionCapabilitiesV1,
    pub history: HistoryCapabilitiesV1,
    pub voice: VoiceCapabilitiesV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInstance {
    pub instance_id: ProviderInstanceId,
    pub runtime_id: String,
    pub display_name: String,
    pub readiness: ProviderReadiness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_reason: Option<String>,
    pub continuation_group_id: String,
    pub models: Vec<ModelDescriptor>,
    pub capabilities: RuntimeCapabilitiesV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCapabilitiesV1 {
    pub version: u32,
    pub project_registration: FeatureAvailability,
    pub project_clone: FeatureAvailability,
    pub confined_file_reads: FeatureAvailability,
    pub terminal_sessions: FeatureAvailability,
    pub curated_git: FeatureAvailability,
    pub worktrees: FeatureAvailability,
    pub checkpoints: FeatureAvailability,
    pub safe_rewind: FeatureAvailability,
    pub trusted_provisioning_scripts: FeatureAvailability,
    pub browser_preview: FeatureAvailability,
    pub browser_automation: FeatureAvailability,
    pub managed_power: FeatureAvailability,
    pub signed_link_updates: FeatureAvailability,
    pub diagnostics: FeatureAvailability,
    pub protocol_version: u32,
    pub minimum_client_version: String,
}

impl HostCapabilitiesV1 {
    pub fn all_unknown(protocol_version: u32, minimum_client_version: impl Into<String>) -> Self {
        let unknown = || FeatureAvailability::unknown("Host has not declared this capability");
        Self {
            version: 1,
            project_registration: unknown(),
            project_clone: unknown(),
            confined_file_reads: unknown(),
            terminal_sessions: unknown(),
            curated_git: unknown(),
            worktrees: unknown(),
            checkpoints: unknown(),
            safe_rewind: unknown(),
            trusted_provisioning_scripts: unknown(),
            browser_preview: unknown(),
            browser_automation: unknown(),
            managed_power: unknown(),
            signed_link_updates: unknown(),
            diagnostics: unknown(),
            protocol_version,
            minimum_client_version: bound_utf8(
                minimum_client_version.into(),
                MAX_DISPLAY_LABEL_BYTES,
            ),
        }
    }
}

impl RuntimeCapabilitiesV1 {
    pub fn all_unknown() -> Self {
        let unknown = || FeatureAvailability::unknown("Provider has not declared this capability");
        Self {
            version: 1,
            thread_lifecycle: ThreadLifecycleCapabilitiesV1 {
                create: unknown(),
                resume: unknown(),
                linked_child: unknown(),
                archive: unknown(),
            },
            turns: TurnCapabilitiesV1 {
                text: unknown(),
                images: unknown(),
                file_references: unknown(),
                interrupt: unknown(),
                queued_follow_up: unknown(),
            },
            interaction: InteractionCapabilitiesV1 {
                approvals: unknown(),
                structured_input: unknown(),
                ask_question: unknown(),
                plans: unknown(),
                todos: unknown(),
            },
            models: ModelCapabilitiesV1 {
                list: unknown(),
                select_before_first_send: unknown(),
                reasoning_configuration: unknown(),
            },
            permissions: PermissionCapabilitiesV1 {
                sandbox_modes: unknown(),
                declared_controls: unknown(),
            },
            history: HistoryCapabilitiesV1 {
                pagination: unknown(),
                hydration: unknown(),
                context_window_metrics: unknown(),
            },
            voice: VoiceCapabilitiesV1 {
                realtime_voice: unknown(),
                transcript_handoff: unknown(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectGitKind {
    Git,
    NonGit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectAvailability {
    Available,
    Missing,
    PermissionDenied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkingCopyLifecycle {
    Provisioning,
    Ready,
    Archived,
    CleanupEligible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadStatus {
    Queued,
    Running,
    Waiting,
    Completed,
    Failed,
    Cancelled,
    Archived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionState {
    None,
    NeedsYou,
    Snoozed,
    Acknowledged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnLifecycle {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSessionLifecycle {
    Starting,
    Connected,
    Disconnected,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSummary {
    pub project_id: ProjectId,
    pub host_id: HostId,
    pub display_name: String,
    pub git_kind: ProjectGitKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
    pub availability: ProjectAvailability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRecord {
    pub summary: ProjectSummary,
    pub root_path: String,
    pub root_identity: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkingCopySummary {
    pub working_copy_id: WorkingCopyId,
    pub project_id: ProjectId,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_revision: Option<String>,
    pub lifecycle: WorkingCopyLifecycle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkingCopyRecord {
    pub summary: WorkingCopySummary,
    pub root_path: String,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadSummary {
    pub thread_id: ThreadId,
    pub host_id: HostId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<ProjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_copy_id: Option<WorkingCopyId>,
    pub runtime_id: String,
    pub provider_instance_id: ProviderInstanceId,
    pub title: String,
    pub status: ThreadStatus,
    pub attention: AttentionState,
    pub updated_at_ms: i64,
    pub route_handle: RouteHandle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadRecord {
    pub summary: ThreadSummary,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_parent_thread_id: Option<ThreadId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnSummary {
    pub turn_id: TurnId,
    pub thread_id: ThreadId,
    pub lifecycle: TurnLifecycle,
    pub started_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<CheckpointId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSessionSummary {
    pub provider_session_id: ProviderSessionId,
    pub thread_id: ThreadId,
    pub provider_instance_id: ProviderInstanceId,
    pub lifecycle: ProviderSessionLifecycle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumable_session_id: Option<String>,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointSummary {
    pub checkpoint_id: CheckpointId,
    pub thread_id: ThreadId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<TurnId>,
    pub commit_oid: String,
    pub reference_name: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteHandleRecord {
    pub route_handle: RouteHandle,
    pub thread_id: ThreadId,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedScriptRecord {
    pub trust_hash: String,
    pub project_id: ProjectId,
    pub command: Vec<String>,
    pub working_directory: String,
    pub trigger: String,
    pub declared_environment: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserProfileRecord {
    pub project_id: ProjectId,
    pub profile_directory: String,
    pub updated_at_ms: i64,
}

/// Durable Host-side receipt for a device work intent.
///
/// `Dispatching` is deliberately an ambiguity fence: after an external
/// provider mutation may have started, recovery reports an unknown outcome
/// and never blindly dispatches the same intent again. The caller must
/// reconcile authoritative Thread history before deciding what to do next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkIntentRecord {
    pub intent_id: String,
    pub origin_credential_id: String,
    pub kind: WorkIntentKind,
    pub request_fingerprint: String,
    pub state: WorkIntentState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<ThreadId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<TurnId>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCatalogV1 {
    pub schema_version: u32,
    pub generation: u64,
    pub host_id: HostId,
    pub host_capabilities: HostCapabilitiesV1,
    pub projects: Vec<ProjectRecord>,
    pub working_copies: Vec<WorkingCopyRecord>,
    pub threads: Vec<ThreadRecord>,
    pub turns: Vec<TurnSummary>,
    pub provider_sessions: Vec<ProviderSessionSummary>,
    pub checkpoints: Vec<CheckpointSummary>,
    pub provider_instances: Vec<ProviderInstance>,
    pub route_handles: Vec<RouteHandleRecord>,
    pub trusted_scripts: Vec<TrustedScriptRecord>,
    pub browser_profiles: Vec<BrowserProfileRecord>,
    #[serde(default)]
    pub work_intents: Vec<WorkIntentRecord>,
}

/// Bounded status safe to disclose under the existing runtime-inspection
/// grant. Project names, paths, Threads, scripts, and browser state are
/// deliberately excluded until dedicated workspace grants exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCommandCenterStatusV1 {
    pub version: u32,
    pub host_id: HostId,
    pub catalog_generation: u64,
    pub host_capabilities: HostCapabilitiesV1,
    pub provider_instances: Vec<ProviderInstance>,
}

impl HostCatalogV1 {
    pub fn empty(host_id: HostId, host_capabilities: HostCapabilitiesV1) -> Self {
        Self {
            schema_version: COMMAND_CENTER_SCHEMA_VERSION,
            generation: 0,
            host_id,
            host_capabilities,
            projects: Vec::new(),
            working_copies: Vec::new(),
            threads: Vec::new(),
            turns: Vec::new(),
            provider_sessions: Vec::new(),
            checkpoints: Vec::new(),
            provider_instances: Vec::new(),
            route_handles: Vec::new(),
            trusted_scripts: Vec::new(),
            browser_profiles: Vec::new(),
            work_intents: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), CatalogValidationError> {
        if self.schema_version != COMMAND_CENTER_SCHEMA_VERSION {
            return Err(CatalogValidationError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_id("host_id", self.host_id.as_str())?;
        validate_count("projects", self.projects.len(), MAX_PROJECTS)?;
        validate_count(
            "working_copies",
            self.working_copies.len(),
            MAX_WORKING_COPIES,
        )?;
        validate_count("threads", self.threads.len(), MAX_THREADS)?;
        validate_count("turns", self.turns.len(), MAX_TURNS)?;
        validate_count(
            "provider sessions",
            self.provider_sessions.len(),
            MAX_PROVIDER_SESSIONS,
        )?;
        validate_count("checkpoints", self.checkpoints.len(), MAX_CHECKPOINTS)?;
        validate_count(
            "provider_instances",
            self.provider_instances.len(),
            MAX_PROVIDER_INSTANCES,
        )?;
        validate_count("route handles", self.route_handles.len(), MAX_ROUTE_HANDLES)?;
        validate_count(
            "trusted scripts",
            self.trusted_scripts.len(),
            MAX_TRUSTED_SCRIPTS,
        )?;
        validate_count(
            "browser profiles",
            self.browser_profiles.len(),
            MAX_BROWSER_PROFILES,
        )?;
        validate_count("work intents", self.work_intents.len(), MAX_WORK_INTENTS)?;
        validate_host_capabilities(&self.host_capabilities)?;

        unique_ids(
            "project_id",
            self.projects
                .iter()
                .map(|record| record.summary.project_id.as_str()),
        )?;
        unique_ids(
            "working_copy_id",
            self.working_copies
                .iter()
                .map(|record| record.summary.working_copy_id.as_str()),
        )?;
        unique_ids(
            "thread_id",
            self.threads
                .iter()
                .map(|record| record.summary.thread_id.as_str()),
        )?;
        unique_ids(
            "turn_id",
            self.turns.iter().map(|record| record.turn_id.as_str()),
        )?;
        unique_ids(
            "provider_session_id",
            self.provider_sessions
                .iter()
                .map(|record| record.provider_session_id.as_str()),
        )?;
        unique_ids(
            "checkpoint_id",
            self.checkpoints
                .iter()
                .map(|record| record.checkpoint_id.as_str()),
        )?;
        unique_ids(
            "provider_instance_id",
            self.provider_instances
                .iter()
                .map(|record| record.instance_id.as_str()),
        )?;
        unique_ids(
            "route_handle",
            self.route_handles
                .iter()
                .map(|record| record.route_handle.as_str()),
        )?;
        unique_work_intent_ids(
            self.work_intents
                .iter()
                .map(|record| record.intent_id.as_str()),
        )?;

        let project_ids = self
            .projects
            .iter()
            .map(|record| record.summary.project_id.as_str())
            .collect::<HashSet<_>>();
        let working_copy_ids = self
            .working_copies
            .iter()
            .map(|record| record.summary.working_copy_id.as_str())
            .collect::<HashSet<_>>();
        let working_copy_projects = self
            .working_copies
            .iter()
            .map(|record| {
                (
                    record.summary.working_copy_id.as_str(),
                    record.summary.project_id.as_str(),
                )
            })
            .collect::<HashMap<_, _>>();
        let provider_runtime_ids = self
            .provider_instances
            .iter()
            .map(|record| (record.instance_id.as_str(), record.runtime_id.as_str()))
            .collect::<HashMap<_, _>>();
        let thread_ids = self
            .threads
            .iter()
            .map(|record| record.summary.thread_id.as_str())
            .collect::<HashSet<_>>();
        let turn_threads = self
            .turns
            .iter()
            .map(|record| (record.turn_id.as_str(), record.thread_id.as_str()))
            .collect::<HashMap<_, _>>();
        let route_threads = self
            .route_handles
            .iter()
            .map(|record| (record.route_handle.as_str(), record.thread_id.as_str()))
            .collect::<HashMap<_, _>>();
        let checkpoint_threads = self
            .checkpoints
            .iter()
            .map(|record| (record.checkpoint_id.as_str(), record.thread_id.as_str()))
            .collect::<HashMap<_, _>>();

        for project in &self.projects {
            validate_label("project display name", &project.summary.display_name)?;
            validate_path("project root", &project.root_path)?;
            validate_label("project root identity", &project.root_identity)?;
            validate_optional_label("project default branch", &project.summary.default_branch)?;
            validate_timestamp("project created_at_ms", project.created_at_ms)?;
            if project.summary.host_id != self.host_id {
                return Err(CatalogValidationError::InvalidReference("project host_id"));
            }
        }
        for working_copy in &self.working_copies {
            validate_label(
                "working copy display name",
                &working_copy.summary.display_name,
            )?;
            validate_path("working copy root", &working_copy.root_path)?;
            validate_optional_label("working copy branch", &working_copy.summary.branch)?;
            validate_optional_label(
                "working copy base revision",
                &working_copy.summary.base_revision,
            )?;
            validate_timestamp("working copy created_at_ms", working_copy.created_at_ms)?;
            validate_optional_timestamp(
                "working copy archived_at_ms",
                working_copy.archived_at_ms,
            )?;
            if !project_ids.contains(working_copy.summary.project_id.as_str())
                || working_copy
                    .archived_at_ms
                    .is_some_and(|archived| archived < working_copy.created_at_ms)
            {
                return Err(CatalogValidationError::InvalidReference("working copy"));
            }
        }
        for thread in &self.threads {
            validate_label("thread title", &thread.summary.title)?;
            validate_label("thread runtime_id", &thread.summary.runtime_id)?;
            validate_timestamp("thread created_at_ms", thread.created_at_ms)?;
            validate_timestamp("thread updated_at_ms", thread.summary.updated_at_ms)?;
            validate_optional_timestamp("thread archived_at_ms", thread.archived_at_ms)?;
            let provider_runtime_id = provider_runtime_ids
                .get(thread.summary.provider_instance_id.as_str())
                .copied();
            let working_copy_project_id = thread
                .summary
                .working_copy_id
                .as_ref()
                .and_then(|id| working_copy_projects.get(id.as_str()).copied());
            let route_thread_id = route_threads
                .get(thread.summary.route_handle.as_str())
                .copied();
            if thread.summary.host_id != self.host_id
                || thread
                    .summary
                    .project_id
                    .as_ref()
                    .is_some_and(|id| !project_ids.contains(id.as_str()))
                || thread
                    .summary
                    .working_copy_id
                    .as_ref()
                    .is_some_and(|id| !working_copy_ids.contains(id.as_str()))
                || thread.summary.working_copy_id.is_some()
                    && working_copy_project_id
                        != thread.summary.project_id.as_ref().map(ProjectId::as_str)
                || provider_runtime_id != Some(thread.summary.runtime_id.as_str())
                || route_thread_id != Some(thread.summary.thread_id.as_str())
                || thread.linked_parent_thread_id.as_ref().is_some_and(|id| {
                    id == &thread.summary.thread_id || !thread_ids.contains(id.as_str())
                })
                || thread
                    .archived_at_ms
                    .is_some_and(|archived| archived < thread.created_at_ms)
            {
                return Err(CatalogValidationError::InvalidReference("thread"));
            }
        }
        for turn in &self.turns {
            validate_id("turn_id", turn.turn_id.as_str())?;
            validate_timestamp("turn started_at_ms", turn.started_at_ms)?;
            validate_optional_timestamp("turn completed_at_ms", turn.completed_at_ms)?;
            if !thread_ids.contains(turn.thread_id.as_str())
                || turn
                    .completed_at_ms
                    .is_some_and(|completed| completed < turn.started_at_ms)
                || turn.checkpoint_id.as_ref().is_some_and(|checkpoint_id| {
                    checkpoint_threads.get(checkpoint_id.as_str()).copied()
                        != Some(turn.thread_id.as_str())
                })
            {
                return Err(CatalogValidationError::InvalidReference("turn"));
            }
        }
        for provider in &self.provider_instances {
            validate_id("provider_instance_id", provider.instance_id.as_str())?;
            validate_label("provider display name", &provider.display_name)?;
            validate_label("runtime_id", &provider.runtime_id)?;
            validate_label("continuation_group_id", &provider.continuation_group_id)?;
            validate_optional_label("provider readiness reason", &provider.readiness_reason)?;
            validate_runtime_capabilities(&provider.capabilities)?;
            validate_count(
                "provider models",
                provider.models.len(),
                MAX_MODELS_PER_PROVIDER,
            )?;
            let mut model_ids = HashSet::new();
            for model in &provider.models {
                validate_label("provider model_id", &model.model_id)?;
                validate_label("provider model display name", &model.display_name)?;
                if !model_ids.insert(model.model_id.as_str()) {
                    return Err(CatalogValidationError::DuplicateId("provider model_id"));
                }
            }
        }
        let mut resumable_provider_sessions = HashSet::new();
        for session in &self.provider_sessions {
            validate_optional_label(
                "provider resumable session_id",
                &session.resumable_session_id,
            )?;
            validate_timestamp("provider session updated_at_ms", session.updated_at_ms)?;
            let thread_provider_id = self
                .threads
                .iter()
                .find(|thread| thread.summary.thread_id == session.thread_id)
                .map(|thread| thread.summary.provider_instance_id.as_str());
            if thread_provider_id != Some(session.provider_instance_id.as_str()) {
                return Err(CatalogValidationError::InvalidReference("provider session"));
            }
            if let Some(resumable_session_id) = session.resumable_session_id.as_deref()
                && !resumable_provider_sessions
                    .insert((session.provider_instance_id.as_str(), resumable_session_id))
            {
                return Err(CatalogValidationError::DuplicateId(
                    "provider resumable session",
                ));
            }
        }
        for checkpoint in &self.checkpoints {
            validate_git_oid(&checkpoint.commit_oid)?;
            validate_checkpoint_reference(&checkpoint.reference_name)?;
            validate_timestamp("checkpoint created_at_ms", checkpoint.created_at_ms)?;
            if !thread_ids.contains(checkpoint.thread_id.as_str())
                || checkpoint.turn_id.as_ref().is_some_and(|turn_id| {
                    turn_threads.get(turn_id.as_str()).copied()
                        != Some(checkpoint.thread_id.as_str())
                })
            {
                return Err(CatalogValidationError::InvalidReference("checkpoint"));
            }
        }
        for route in &self.route_handles {
            validate_timestamp("route created_at_ms", route.created_at_ms)?;
            validate_optional_timestamp("route expires_at_ms", route.expires_at_ms)?;
            if !thread_ids.contains(route.thread_id.as_str())
                || route
                    .expires_at_ms
                    .is_some_and(|expires| expires < route.created_at_ms)
            {
                return Err(CatalogValidationError::InvalidReference("route handle"));
            }
        }
        let mut trusted_script_hashes = HashSet::new();
        for script in &self.trusted_scripts {
            validate_sha256("trusted script hash", &script.trust_hash)?;
            validate_count(
                "trusted script command",
                script.command.len(),
                MAX_COMMAND_ARGUMENTS,
            )?;
            validate_count(
                "trusted script environment",
                script.declared_environment.len(),
                MAX_DECLARED_ENVIRONMENT,
            )?;
            if script.command.is_empty()
                || script
                    .command
                    .iter()
                    .any(|argument| validate_argument("trusted script argument", argument).is_err())
                || script
                    .declared_environment
                    .iter()
                    .any(|value| validate_argument("trusted script environment", value).is_err())
                || !project_ids.contains(script.project_id.as_str())
                || !trusted_script_hashes.insert(script.trust_hash.as_str())
            {
                return Err(CatalogValidationError::InvalidReference("trusted script"));
            }
            validate_path(
                "trusted script working directory",
                &script.working_directory,
            )?;
            validate_label("trusted script trigger", &script.trigger)?;
        }
        let mut browser_project_ids = HashSet::new();
        for profile in &self.browser_profiles {
            validate_path("browser profile directory", &profile.profile_directory)?;
            validate_timestamp("browser profile updated_at_ms", profile.updated_at_ms)?;
            if !project_ids.contains(profile.project_id.as_str())
                || !browser_project_ids.insert(profile.project_id.as_str())
            {
                return Err(CatalogValidationError::InvalidReference("browser profile"));
            }
        }
        for intent in &self.work_intents {
            validate_id(
                "work intent origin credential",
                &intent.origin_credential_id,
            )?;
            validate_sha256(
                "work intent request fingerprint",
                &intent.request_fingerprint,
            )?;
            validate_timestamp("work intent created_at_ms", intent.created_at_ms)?;
            validate_timestamp("work intent updated_at_ms", intent.updated_at_ms)?;
            let referenced_thread = intent.thread_id.as_ref().map(ThreadId::as_str);
            let referenced_turn_thread = intent
                .turn_id
                .as_ref()
                .and_then(|turn_id| turn_threads.get(turn_id.as_str()).copied());
            if intent.updated_at_ms < intent.created_at_ms
                || referenced_thread.is_some_and(|thread_id| !thread_ids.contains(thread_id))
                || intent.turn_id.is_some() && referenced_turn_thread.is_none()
                || referenced_turn_thread
                    .is_some_and(|thread_id| Some(thread_id) != referenced_thread)
                || matches!(intent.kind, WorkIntentKind::CreateThread)
                    && (intent.thread_id.is_none() || intent.turn_id.is_some())
                || matches!(intent.kind, WorkIntentKind::SendMessage) && intent.thread_id.is_none()
                || matches!(intent.state, WorkIntentState::Succeeded)
                    && matches!(intent.kind, WorkIntentKind::SendMessage)
                    && intent.turn_id.is_none()
            {
                return Err(CatalogValidationError::InvalidReference("work intent"));
            }
        }
        let status_size = serde_json::to_vec(&self.command_center_status())
            .map_err(|_| CatalogValidationError::InvalidCapability)?
            .len();
        if status_size > MAX_COMMAND_CENTER_STATUS_BYTES {
            return Err(CatalogValidationError::StatusTooLarge);
        }
        Ok(())
    }

    pub fn validate_transition(&self, next: &Self) -> Result<(), CatalogValidationError> {
        next.validate()?;
        if self.host_id != next.host_id || next.generation != self.generation.saturating_add(1) {
            return Err(CatalogValidationError::InvalidGeneration);
        }
        for current in &self.threads {
            if let Some(updated) = next
                .threads
                .iter()
                .find(|candidate| candidate.summary.thread_id == current.summary.thread_id)
                && (updated.summary.runtime_id != current.summary.runtime_id
                    || updated.summary.provider_instance_id != current.summary.provider_instance_id)
            {
                return Err(CatalogValidationError::ImmutableThreadRuntime);
            }
        }
        for current in &self.provider_sessions {
            let Some(updated) = next
                .provider_sessions
                .iter()
                .find(|candidate| candidate.provider_session_id == current.provider_session_id)
            else {
                return Err(CatalogValidationError::InvalidProviderSessionTransition);
            };
            let resumable_session_is_valid = current.resumable_session_id
                == updated.resumable_session_id
                || current.resumable_session_id.is_none() && updated.resumable_session_id.is_some();
            if current.thread_id != updated.thread_id
                || current.provider_instance_id != updated.provider_instance_id
                || updated.updated_at_ms < current.updated_at_ms
                || !resumable_session_is_valid
            {
                return Err(CatalogValidationError::InvalidProviderSessionTransition);
            }
        }
        for current in &self.work_intents {
            let Some(updated) = next
                .work_intents
                .iter()
                .find(|candidate| candidate.intent_id == current.intent_id)
            else {
                return Err(CatalogValidationError::InvalidWorkIntentTransition);
            };
            let state_is_valid = current.state == updated.state
                || matches!(
                    (current.state, updated.state),
                    (WorkIntentState::Reserved, WorkIntentState::Dispatching)
                        | (WorkIntentState::Reserved, WorkIntentState::Succeeded)
                        | (WorkIntentState::Dispatching, WorkIntentState::Succeeded)
                );
            let turn_is_valid = current.turn_id == updated.turn_id
                || current.turn_id.is_none()
                    && updated.turn_id.is_some()
                    && matches!(updated.state, WorkIntentState::Succeeded);
            if current.origin_credential_id != updated.origin_credential_id
                || current.kind != updated.kind
                || current.request_fingerprint != updated.request_fingerprint
                || current.thread_id != updated.thread_id
                || current.created_at_ms != updated.created_at_ms
                || updated.updated_at_ms < current.updated_at_ms
                || !state_is_valid
                || !turn_is_valid
            {
                return Err(CatalogValidationError::InvalidWorkIntentTransition);
            }
        }
        Ok(())
    }

    pub fn command_center_status(&self) -> HostCommandCenterStatusV1 {
        HostCommandCenterStatusV1 {
            version: 1,
            host_id: self.host_id.clone(),
            catalog_generation: self.generation,
            host_capabilities: self.host_capabilities.clone(),
            provider_instances: self.provider_instances.clone(),
        }
    }

    pub fn command_center_status_for_runtime_ids(
        &self,
        runtime_ids: &[String],
    ) -> HostCommandCenterStatusV1 {
        let mut status = self.command_center_status();
        status
            .provider_instances
            .retain(|provider| runtime_ids.contains(&provider.runtime_id));
        status
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CatalogValidationError {
    #[error("unsupported catalog schema {0}")]
    UnsupportedSchema(u32),
    #[error("invalid opaque {0}")]
    InvalidId(&'static str),
    #[error("duplicate opaque {0}")]
    DuplicateId(&'static str),
    #[error("{0} exceeds its catalog bound")]
    TooMany(&'static str),
    #[error("invalid bounded {0}")]
    InvalidText(&'static str),
    #[error("invalid catalog reference: {0}")]
    InvalidReference(&'static str),
    #[error("invalid capability declaration")]
    InvalidCapability,
    #[error("command-center status exceeds its serialized bound")]
    StatusTooLarge,
    #[error("invalid catalog generation transition")]
    InvalidGeneration,
    #[error("thread runtime and provider instance are immutable")]
    ImmutableThreadRuntime,
    #[error("invalid durable provider-session transition")]
    InvalidProviderSessionTransition,
    #[error("invalid durable work-intent transition")]
    InvalidWorkIntentTransition,
}

pub fn valid_opaque_id(value: &str) -> bool {
    value.len() == OPAQUE_ID_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn validate_id(kind: &'static str, value: &str) -> Result<(), CatalogValidationError> {
    valid_opaque_id(value)
        .then_some(())
        .ok_or(CatalogValidationError::InvalidId(kind))
}

fn unique_ids<'a>(
    kind: &'static str,
    values: impl Iterator<Item = &'a str>,
) -> Result<(), CatalogValidationError> {
    let mut seen = HashSet::new();
    for value in values {
        validate_id(kind, value)?;
        if !seen.insert(value) {
            return Err(CatalogValidationError::DuplicateId(kind));
        }
    }
    Ok(())
}

fn unique_work_intent_ids<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<(), CatalogValidationError> {
    let mut seen = HashSet::new();
    for value in values {
        if value.is_empty()
            || value.len() > MAX_WORK_INTENT_ID_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CatalogValidationError::InvalidId("work intent"));
        }
        if !seen.insert(value) {
            return Err(CatalogValidationError::DuplicateId("work intent"));
        }
    }
    Ok(())
}

fn validate_count(
    kind: &'static str,
    count: usize,
    maximum: usize,
) -> Result<(), CatalogValidationError> {
    (count <= maximum)
        .then_some(())
        .ok_or(CatalogValidationError::TooMany(kind))
}

fn validate_label(kind: &'static str, value: &str) -> Result<(), CatalogValidationError> {
    (!value.trim().is_empty()
        && value.len() <= MAX_DISPLAY_LABEL_BYTES
        && !value.chars().any(char::is_control))
    .then_some(())
    .ok_or(CatalogValidationError::InvalidText(kind))
}

fn validate_optional_label(
    kind: &'static str,
    value: &Option<String>,
) -> Result<(), CatalogValidationError> {
    if let Some(value) = value {
        validate_label(kind, value)?;
    }
    Ok(())
}

fn validate_availability(value: &FeatureAvailability) -> Result<(), CatalogValidationError> {
    validate_optional_label("capability reason", &value.reason)
}

fn validate_host_capabilities(
    capabilities: &HostCapabilitiesV1,
) -> Result<(), CatalogValidationError> {
    if capabilities.version != 1 {
        return Err(CatalogValidationError::InvalidCapability);
    }
    validate_label(
        "minimum client version",
        &capabilities.minimum_client_version,
    )?;
    for availability in [
        &capabilities.project_registration,
        &capabilities.project_clone,
        &capabilities.confined_file_reads,
        &capabilities.terminal_sessions,
        &capabilities.curated_git,
        &capabilities.worktrees,
        &capabilities.checkpoints,
        &capabilities.safe_rewind,
        &capabilities.trusted_provisioning_scripts,
        &capabilities.browser_preview,
        &capabilities.browser_automation,
        &capabilities.managed_power,
        &capabilities.signed_link_updates,
        &capabilities.diagnostics,
    ] {
        validate_availability(availability)?;
    }
    Ok(())
}

fn validate_runtime_capabilities(
    capabilities: &RuntimeCapabilitiesV1,
) -> Result<(), CatalogValidationError> {
    if capabilities.version != 1 {
        return Err(CatalogValidationError::InvalidCapability);
    }
    for availability in [
        &capabilities.thread_lifecycle.create,
        &capabilities.thread_lifecycle.resume,
        &capabilities.thread_lifecycle.linked_child,
        &capabilities.thread_lifecycle.archive,
        &capabilities.turns.text,
        &capabilities.turns.images,
        &capabilities.turns.file_references,
        &capabilities.turns.interrupt,
        &capabilities.turns.queued_follow_up,
        &capabilities.interaction.approvals,
        &capabilities.interaction.structured_input,
        &capabilities.interaction.ask_question,
        &capabilities.interaction.plans,
        &capabilities.interaction.todos,
        &capabilities.models.list,
        &capabilities.models.select_before_first_send,
        &capabilities.models.reasoning_configuration,
        &capabilities.permissions.sandbox_modes,
        &capabilities.permissions.declared_controls,
        &capabilities.history.pagination,
        &capabilities.history.hydration,
        &capabilities.history.context_window_metrics,
        &capabilities.voice.realtime_voice,
        &capabilities.voice.transcript_handoff,
    ] {
        validate_availability(availability)?;
    }
    Ok(())
}

fn validate_path(kind: &'static str, value: &str) -> Result<(), CatalogValidationError> {
    (!value.is_empty() && value.len() <= MAX_PATH_BYTES && !value.chars().any(char::is_control))
        .then_some(())
        .ok_or(CatalogValidationError::InvalidText(kind))
}

fn validate_argument(kind: &'static str, value: &str) -> Result<(), CatalogValidationError> {
    (!value.is_empty() && value.len() <= MAX_PATH_BYTES && !value.chars().any(char::is_control))
        .then_some(())
        .ok_or(CatalogValidationError::InvalidText(kind))
}

fn validate_timestamp(kind: &'static str, value: i64) -> Result<(), CatalogValidationError> {
    (value >= 0)
        .then_some(())
        .ok_or(CatalogValidationError::InvalidText(kind))
}

fn validate_optional_timestamp(
    kind: &'static str,
    value: Option<i64>,
) -> Result<(), CatalogValidationError> {
    value.map_or(Ok(()), |value| validate_timestamp(kind, value))
}

fn validate_sha256(kind: &'static str, value: &str) -> Result<(), CatalogValidationError> {
    (value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
    .then_some(())
    .ok_or(CatalogValidationError::InvalidText(kind))
}

fn validate_git_oid(value: &str) -> Result<(), CatalogValidationError> {
    (matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
    .then_some(())
    .ok_or(CatalogValidationError::InvalidText("checkpoint commit_oid"))
}

fn validate_checkpoint_reference(value: &str) -> Result<(), CatalogValidationError> {
    (value.starts_with("refs/remora/checkpoints/")
        && value.len() <= MAX_PATH_BYTES
        && !value.chars().any(char::is_control))
    .then_some(())
    .ok_or(CatalogValidationError::InvalidText(
        "checkpoint reference_name",
    ))
}

fn bound_utf8(mut value: String, maximum: usize) -> String {
    if value.len() <= maximum {
        return value;
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_catalog() -> HostCatalogV1 {
        let host_id = HostId("abcdefghijklmnopqrstuv".to_string());
        let provider_instance_id = ProviderInstanceId("bcdefghijklmnopqrstuvw".to_string());
        let project_id = ProjectId("cdefghijklmnopqrstuvwx".to_string());
        let working_copy_id = WorkingCopyId("defghijklmnopqrstuvwxy".to_string());
        let thread_id = ThreadId("efghijklmnopqrstuvwxyz".to_string());
        let turn_id = TurnId("fghijklmnopqrstuvwxyza".to_string());
        let provider_session_id = ProviderSessionId("ghijklmnopqrstuvwxyzab".to_string());
        let checkpoint_id = CheckpointId("hijklmnopqrstuvwxyzabc".to_string());
        let route_handle = RouteHandle("ijklmnopqrstuvwxyzabcd".to_string());
        let mut catalog =
            HostCatalogV1::empty(host_id.clone(), HostCapabilitiesV1::all_unknown(2, "0.1.0"));
        catalog.provider_instances.push(ProviderInstance {
            instance_id: provider_instance_id.clone(),
            runtime_id: "codex".to_string(),
            display_name: "Codex".to_string(),
            readiness: ProviderReadiness::Ready,
            readiness_reason: None,
            continuation_group_id: "codex-default".to_string(),
            models: vec![ModelDescriptor {
                model_id: "gpt-5".to_string(),
                display_name: "GPT-5".to_string(),
                is_default: true,
            }],
            capabilities: RuntimeCapabilitiesV1::all_unknown(),
        });
        catalog.projects.push(ProjectRecord {
            summary: ProjectSummary {
                project_id: project_id.clone(),
                host_id,
                display_name: "Remora".to_string(),
                git_kind: ProjectGitKind::Git,
                default_branch: Some("main".to_string()),
                availability: ProjectAvailability::Available,
            },
            root_path: "/tmp/remora".to_string(),
            root_identity: "device:inode".to_string(),
            created_at_ms: 1,
        });
        catalog.working_copies.push(WorkingCopyRecord {
            summary: WorkingCopySummary {
                working_copy_id: working_copy_id.clone(),
                project_id: project_id.clone(),
                display_name: "Command center".to_string(),
                branch: Some("remora/thread".to_string()),
                base_revision: Some("a".repeat(40)),
                lifecycle: WorkingCopyLifecycle::Ready,
            },
            root_path: "/tmp/remora-worktree".to_string(),
            created_at_ms: 2,
            archived_at_ms: None,
        });
        catalog.threads.push(ThreadRecord {
            summary: ThreadSummary {
                thread_id: thread_id.clone(),
                host_id: catalog.host_id.clone(),
                project_id: Some(project_id.clone()),
                working_copy_id: Some(working_copy_id),
                runtime_id: "codex".to_string(),
                provider_instance_id: provider_instance_id.clone(),
                title: "Build command center".to_string(),
                status: ThreadStatus::Running,
                attention: AttentionState::None,
                updated_at_ms: 3,
                route_handle: route_handle.clone(),
            },
            created_at_ms: 2,
            linked_parent_thread_id: None,
            archived_at_ms: None,
        });
        catalog.turns.push(TurnSummary {
            turn_id: turn_id.clone(),
            thread_id: thread_id.clone(),
            lifecycle: TurnLifecycle::Completed,
            started_at_ms: 3,
            completed_at_ms: Some(4),
            checkpoint_id: Some(checkpoint_id.clone()),
        });
        catalog.provider_sessions.push(ProviderSessionSummary {
            provider_session_id,
            thread_id: thread_id.clone(),
            provider_instance_id,
            lifecycle: ProviderSessionLifecycle::Connected,
            resumable_session_id: Some("provider-session".to_string()),
            updated_at_ms: 4,
        });
        catalog.checkpoints.push(CheckpointSummary {
            checkpoint_id,
            thread_id: thread_id.clone(),
            turn_id: Some(turn_id),
            commit_oid: "a".repeat(40),
            reference_name: "refs/remora/checkpoints/thread/turn".to_string(),
            created_at_ms: 4,
        });
        catalog.route_handles.push(RouteHandleRecord {
            route_handle,
            thread_id,
            created_at_ms: 2,
            expires_at_ms: None,
        });
        catalog.trusted_scripts.push(TrustedScriptRecord {
            trust_hash: "b".repeat(64),
            project_id: project_id.clone(),
            command: vec!["make".to_string(), "bootstrap".to_string()],
            working_directory: "/tmp/remora".to_string(),
            trigger: "working_copy_created".to_string(),
            declared_environment: vec!["CI=1".to_string()],
        });
        catalog.browser_profiles.push(BrowserProfileRecord {
            project_id,
            profile_directory: "/tmp/remora-browser".to_string(),
            updated_at_ms: 4,
        });
        catalog
    }

    #[test]
    fn opaque_ids_are_exact_base64url_128_bit_values() {
        assert!(valid_opaque_id("abcdefghijklmnopqrstuv"));
        assert!(!valid_opaque_id("short"));
        assert!(!valid_opaque_id("abcdefghijklmnopqrstu!"));
    }

    #[test]
    fn availability_reasons_are_bounded_on_utf8_boundaries() {
        let availability = FeatureAvailability::unavailable("🦀".repeat(100));
        let reason = availability.reason.expect("reason");
        assert!(reason.len() <= MAX_DISPLAY_LABEL_BYTES);
        assert!(reason.is_char_boundary(reason.len()));
    }

    #[test]
    fn command_center_status_excludes_workspace_content() {
        let catalog = HostCatalogV1::empty(
            HostId("abcdefghijklmnopqrstuv".to_string()),
            HostCapabilitiesV1::all_unknown(2, "0.1.0"),
        );
        let value = serde_json::to_value(catalog.command_center_status()).unwrap();
        assert_eq!(value["version"], 1);
        assert!(value.get("projects").is_none());
        assert!(value.get("threads").is_none());
        assert!(value.get("trusted_scripts").is_none());
        assert!(value.get("browser_profiles").is_none());
    }

    #[test]
    fn command_center_status_fields_are_bounded_at_catalog_ingress() {
        let mut catalog = HostCatalogV1::empty(
            HostId("abcdefghijklmnopqrstuv".to_string()),
            HostCapabilitiesV1::all_unknown(2, "0.1.0"),
        );
        catalog.provider_instances.push(ProviderInstance {
            instance_id: ProviderInstanceId("bcdefghijklmnopqrstuvw".to_string()),
            runtime_id: "codex".to_string(),
            display_name: "Codex".to_string(),
            readiness: ProviderReadiness::Unavailable,
            readiness_reason: Some("x".repeat(MAX_DISPLAY_LABEL_BYTES + 1)),
            continuation_group_id: "codex".to_string(),
            models: Vec::new(),
            capabilities: RuntimeCapabilitiesV1::all_unknown(),
        });

        assert_eq!(
            catalog.validate(),
            Err(CatalogValidationError::InvalidText(
                "provider readiness reason"
            ))
        );
    }

    #[test]
    fn command_center_status_filters_provider_instances_to_the_runtime_grant() {
        let mut catalog = HostCatalogV1::empty(
            HostId("abcdefghijklmnopqrstuv".to_string()),
            HostCapabilitiesV1::all_unknown(2, "0.1.0"),
        );
        for (instance_id, runtime_id) in [
            ("bcdefghijklmnopqrstuvw", "codex"),
            ("cdefghijklmnopqrstuvwx", "claude"),
        ] {
            catalog.provider_instances.push(ProviderInstance {
                instance_id: ProviderInstanceId(instance_id.to_string()),
                runtime_id: runtime_id.to_string(),
                display_name: runtime_id.to_string(),
                readiness: ProviderReadiness::Ready,
                readiness_reason: None,
                continuation_group_id: runtime_id.to_string(),
                models: Vec::new(),
                capabilities: RuntimeCapabilitiesV1::all_unknown(),
            });
        }

        let status = catalog.command_center_status_for_runtime_ids(&["codex".to_string()]);
        assert_eq!(status.provider_instances.len(), 1);
        assert_eq!(status.provider_instances[0].runtime_id, "codex");
    }

    #[test]
    fn complete_catalog_graph_is_bounded_and_relationally_valid() {
        full_catalog().validate().expect("valid catalog");
    }

    #[test]
    fn work_intent_receipts_are_bounded_and_reference_authoritative_domain_records() {
        let mut catalog = full_catalog();
        catalog.work_intents.push(WorkIntentRecord {
            intent_id: "device-intent-1".to_string(),
            origin_credential_id: "jklmnopqrstuvwxyzabcde".to_string(),
            kind: WorkIntentKind::SendMessage,
            request_fingerprint: "c".repeat(64),
            state: WorkIntentState::Succeeded,
            thread_id: Some(catalog.threads[0].summary.thread_id.clone()),
            turn_id: Some(catalog.turns[0].turn_id.clone()),
            created_at_ms: 3,
            updated_at_ms: 4,
        });
        catalog.validate().expect("valid work intent receipt");

        catalog.work_intents[0].turn_id = Some(TurnId("klmnopqrstuvwxyzabcdef".to_string()));
        assert_eq!(
            catalog.validate(),
            Err(CatalogValidationError::InvalidReference("work intent"))
        );
    }

    #[test]
    fn work_intent_transition_never_allows_replay_or_identity_rewrite() {
        let mut current = full_catalog();
        current.work_intents.push(WorkIntentRecord {
            intent_id: "device-intent-1".to_string(),
            origin_credential_id: "jklmnopqrstuvwxyzabcde".to_string(),
            kind: WorkIntentKind::SendMessage,
            request_fingerprint: "c".repeat(64),
            state: WorkIntentState::Reserved,
            thread_id: Some(current.threads[0].summary.thread_id.clone()),
            turn_id: None,
            created_at_ms: 3,
            updated_at_ms: 3,
        });
        current.validate().expect("valid reservation");

        let mut dispatching = current.clone();
        dispatching.generation += 1;
        dispatching.work_intents[0].state = WorkIntentState::Dispatching;
        dispatching.work_intents[0].updated_at_ms = 4;
        current
            .validate_transition(&dispatching)
            .expect("forward transition");

        let mut replayable = dispatching.clone();
        replayable.generation += 1;
        replayable.work_intents[0].state = WorkIntentState::Reserved;
        assert_eq!(
            dispatching.validate_transition(&replayable),
            Err(CatalogValidationError::InvalidWorkIntentTransition)
        );

        let mut removed = dispatching.clone();
        removed.generation += 1;
        removed.work_intents.clear();
        assert_eq!(
            dispatching.validate_transition(&removed),
            Err(CatalogValidationError::InvalidWorkIntentTransition)
        );
    }

    #[test]
    fn catalog_rejects_cross_project_working_copy_and_missing_route() {
        let mut catalog = full_catalog();
        catalog.threads[0].summary.project_id = None;
        assert_eq!(
            catalog.validate(),
            Err(CatalogValidationError::InvalidReference("thread"))
        );

        let mut catalog = full_catalog();
        catalog.route_handles.clear();
        assert_eq!(
            catalog.validate(),
            Err(CatalogValidationError::InvalidReference("thread"))
        );
    }

    #[test]
    fn catalog_rejects_mismatched_provider_session_and_checkpoint_turn() {
        let mut catalog = full_catalog();
        catalog.provider_sessions[0].provider_instance_id =
            ProviderInstanceId("jklmnopqrstuvwxyzabcde".to_string());
        assert_eq!(
            catalog.validate(),
            Err(CatalogValidationError::InvalidReference("provider session"))
        );

        let mut catalog = full_catalog();
        catalog.turns[0].checkpoint_id = Some(CheckpointId("jklmnopqrstuvwxyzabcde".to_string()));
        assert_eq!(
            catalog.validate(),
            Err(CatalogValidationError::InvalidReference("turn"))
        );

        let mut catalog = full_catalog();
        catalog.checkpoints[0].turn_id = Some(TurnId("jklmnopqrstuvwxyzabcde".to_string()));
        assert_eq!(
            catalog.validate(),
            Err(CatalogValidationError::InvalidReference("checkpoint"))
        );
    }

    #[test]
    fn provider_session_binding_is_unique_and_transition_immutable() {
        let current = full_catalog();
        let mut duplicate = current.clone();
        duplicate.provider_sessions.push(ProviderSessionSummary {
            provider_session_id: ProviderSessionId("lmnopqrstuvwxyzabcdefg".to_string()),
            ..duplicate.provider_sessions[0].clone()
        });
        assert_eq!(
            duplicate.validate(),
            Err(CatalogValidationError::DuplicateId(
                "provider resumable session"
            ))
        );

        let mut rebound = current.clone();
        rebound.generation += 1;
        rebound.provider_sessions[0].resumable_session_id = Some("different-session".to_string());
        assert_eq!(
            current.validate_transition(&rebound),
            Err(CatalogValidationError::InvalidProviderSessionTransition)
        );

        let mut removed = current.clone();
        removed.generation += 1;
        removed.provider_sessions.clear();
        assert_eq!(
            current.validate_transition(&removed),
            Err(CatalogValidationError::InvalidProviderSessionTransition)
        );
    }

    #[test]
    fn catalog_rejects_previously_unbounded_collections_and_strings() {
        let mut catalog = full_catalog();
        catalog.route_handles = vec![catalog.route_handles[0].clone(); MAX_ROUTE_HANDLES + 1];
        assert_eq!(
            catalog.validate(),
            Err(CatalogValidationError::TooMany("route handles"))
        );

        let mut catalog = full_catalog();
        catalog.trusted_scripts[0].command =
            vec!["argument".to_string(); MAX_COMMAND_ARGUMENTS + 1];
        assert_eq!(
            catalog.validate(),
            Err(CatalogValidationError::TooMany("trusted script command"))
        );

        let mut catalog = full_catalog();
        catalog.projects[0].root_identity = "x".repeat(MAX_DISPLAY_LABEL_BYTES + 1);
        assert_eq!(
            catalog.validate(),
            Err(CatalogValidationError::InvalidText("project root identity"))
        );
    }
}
