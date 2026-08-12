//! Durable Remora command-center domain records.
//!
//! These types are provider-neutral and Host-owned. They intentionally avoid
//! paths, provider names, and display labels as identity.

use std::collections::HashSet;

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
pub const MAX_PROVIDER_INSTANCES: usize = 64;
pub const MAX_MODELS_PER_PROVIDER: usize = 256;
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
            "provider_instances",
            self.provider_instances.len(),
            MAX_PROVIDER_INSTANCES,
        )?;
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
        let provider_ids = self
            .provider_instances
            .iter()
            .map(|record| record.instance_id.as_str())
            .collect::<HashSet<_>>();
        let thread_ids = self
            .threads
            .iter()
            .map(|record| record.summary.thread_id.as_str())
            .collect::<HashSet<_>>();

        for project in &self.projects {
            validate_label("project display name", &project.summary.display_name)?;
            validate_path("project root", &project.root_path)?;
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
            if !project_ids.contains(working_copy.summary.project_id.as_str()) {
                return Err(CatalogValidationError::InvalidReference(
                    "working copy project_id",
                ));
            }
        }
        for thread in &self.threads {
            validate_label("thread title", &thread.summary.title)?;
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
                || !provider_ids.contains(thread.summary.provider_instance_id.as_str())
            {
                return Err(CatalogValidationError::InvalidReference("thread"));
            }
        }
        for turn in &self.turns {
            validate_id("turn_id", turn.turn_id.as_str())?;
            if !thread_ids.contains(turn.thread_id.as_str()) {
                return Err(CatalogValidationError::InvalidReference("turn thread_id"));
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
            for model in &provider.models {
                validate_label("provider model_id", &model.model_id)?;
                validate_label("provider model display name", &model.display_name)?;
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
}
