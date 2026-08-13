//! Host-owned durable command-center catalog.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use fd_lock::RwLock;
use rand::RngCore;
use remora_bridge_core::command_center::{
    AttentionState, HostCapabilitiesV1, HostCatalogV1, HostId, MAX_DISPLAY_LABEL_BYTES,
    OPAQUE_ID_LENGTH, ProviderInstance, ProviderInstanceId, ProviderReadiness, ProviderSessionId,
    ProviderSessionLifecycle, ProviderSessionSummary, RouteHandle, RouteHandleRecord,
    RuntimeCapabilitiesV1, ThreadId, ThreadRecord, ThreadStatus, ThreadSummary, TurnId,
    TurnLifecycle, TurnSummary, WorkIntentKind, WorkIntentRecord, WorkIntentState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const JOURNAL_COMPACT_BYTES: u64 = 4 * 1024 * 1024;

pub struct HostCatalogStore {
    snapshot_path: PathBuf,
    journal_path: PathBuf,
    file_lock: Mutex<RwLock<File>>,
    state: Mutex<HostCatalogV1>,
}

#[derive(Debug)]
pub enum CatalogCommit<T> {
    Durable(T),
    CommittedUnknown { value: T, error: anyhow::Error },
}

impl<T> CatalogCommit<T> {
    pub fn value(&self) -> &T {
        match self {
            Self::Durable(value) | Self::CommittedUnknown { value, .. } => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkIntentPreparation {
    Execute(WorkIntentRecord),
    Reserved(WorkIntentRecord),
    Succeeded(WorkIntentRecord),
    OutcomeUnknown(WorkIntentRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderThreadBinding {
    pub thread_id: ThreadId,
    pub provider_session_id: ProviderSessionId,
    pub provider_instance_id: ProviderInstanceId,
    pub runtime_id: String,
    pub provider_thread_id: String,
}

impl HostCatalogStore {
    pub fn open_default() -> anyhow::Result<Self> {
        Self::open(
            crate::paths::host_catalog_file()?,
            crate::paths::host_catalog_journal_file()?,
            HostCapabilitiesV1::all_unknown(2, crate::binary_version()),
        )
    }

    pub fn open(
        snapshot_path: PathBuf,
        journal_path: PathBuf,
        initial_capabilities: HostCapabilitiesV1,
    ) -> anyhow::Result<Self> {
        let parent = snapshot_path
            .parent()
            .ok_or_else(|| anyhow!("catalog path has no parent"))?;
        fs::create_dir_all(parent)
            .with_context(|| format!("creating catalog directory {}", parent.display()))?;
        set_mode_0700(parent)?;

        let lock_path = snapshot_path.with_extension("lock");
        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("opening catalog lock {}", lock_path.display()))?;
        set_mode_0600(&lock_path)?;
        let mut file_lock = RwLock::new(lock_file);
        let _guard = file_lock
            .try_write()
            .map_err(|_| anyhow!("another process is updating the Host catalog"))?;

        let snapshot = load_snapshot(&snapshot_path);
        let journal = recover_from_journal(&journal_path)?;
        let state = match (snapshot, journal) {
            (Ok(Some(snapshot)), Some(journal)) if journal.generation > snapshot.generation => {
                if journal.host_id != snapshot.host_id {
                    return Err(anyhow!(
                        "Host catalog journal identity does not match snapshot"
                    ));
                }
                persist_snapshot(&snapshot_path, &journal)?;
                journal
            }
            (Ok(Some(snapshot)), _) => snapshot,
            (Ok(None), Some(journal)) | (Err(_), Some(journal)) => {
                persist_snapshot(&snapshot_path, &journal)?;
                journal
            }
            (Ok(None), None) => {
                let state = HostCatalogV1::empty(random_host_id(), initial_capabilities);
                state.validate().context("validating new Host catalog")?;
                append_journal(&journal_path, &state)?;
                persist_snapshot(&snapshot_path, &state)?;
                state
            }
            (Err(snapshot_error), None) => {
                return Err(snapshot_error).context(
                    "Host catalog is invalid and no checksum-valid recovery entry exists",
                );
            }
        };
        drop(_guard);

        Ok(Self {
            snapshot_path,
            journal_path,
            file_lock: Mutex::new(file_lock),
            state: Mutex::new(state),
        })
    }

    pub fn snapshot(&self) -> HostCatalogV1 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn transact<T>(
        &self,
        mutation: impl FnOnce(&mut HostCatalogV1) -> anyhow::Result<T>,
    ) -> anyhow::Result<CatalogCommit<T>> {
        self.transact_maybe(|catalog| mutation(catalog).map(|value| (value, true)))
    }

    fn transact_maybe<T>(
        &self,
        mutation: impl FnOnce(&mut HostCatalogV1) -> anyhow::Result<(T, bool)>,
    ) -> anyhow::Result<CatalogCommit<T>> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut file_lock = self
            .file_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _guard = file_lock
            .try_write()
            .map_err(|_| anyhow!("another process is updating the Host catalog"))?;

        let mut next = state.clone();
        let (result, changed) = mutation(&mut next)?;
        if !changed {
            return Ok(CatalogCommit::Durable(result));
        }
        next.generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("Host catalog generation exhausted"))?;
        state
            .validate_transition(&next)
            .context("rejecting invalid Host catalog mutation")?;

        append_journal(&self.journal_path, &next)?;
        *state = next;
        let mirror_result = persist_snapshot(&self.snapshot_path, &state)
            .and_then(|()| compact_journal_if_needed(&self.journal_path, &state));
        match mirror_result {
            Ok(()) => Ok(CatalogCommit::Durable(result)),
            Err(error) => Ok(CatalogCommit::CommittedUnknown {
                value: result,
                error,
            }),
        }
    }

    /// Bind an upstream provider Thread to one durable Host Scratch Thread.
    ///
    /// Replays return the existing binding without mutating the catalog. A
    /// runtime with multiple named provider instances is deliberately
    /// rejected until the caller selects an explicit instance.
    pub fn bind_provider_thread(
        &self,
        runtime_id: &str,
        display_name: &str,
        provider_thread_id: &str,
        now_ms: i64,
    ) -> anyhow::Result<CatalogCommit<ProviderThreadBinding>> {
        validate_bounded_label("runtime_id", runtime_id)?;
        validate_bounded_label("provider display name", display_name)?;
        validate_bounded_label("provider thread_id", provider_thread_id)?;
        if now_ms < 0 {
            return Err(anyhow!("provider Thread timestamp is invalid"));
        }

        self.transact_maybe(|catalog| {
            let existing = catalog
                .provider_sessions
                .iter()
                .filter(|session| {
                    session.resumable_session_id.as_deref() == Some(provider_thread_id)
                        && catalog.provider_instances.iter().any(|provider| {
                            provider.instance_id == session.provider_instance_id
                                && provider.runtime_id == runtime_id
                        })
                })
                .map(|session| provider_thread_binding(catalog, session))
                .collect::<anyhow::Result<Vec<_>>>()?;
            match existing.as_slice() {
                [binding] => return Ok((binding.clone(), false)),
                [] => {}
                _ => return Err(anyhow!("provider Thread binding is ambiguous")),
            }

            let matching_provider_ids = catalog
                .provider_instances
                .iter()
                .filter(|provider| provider.runtime_id == runtime_id)
                .map(|provider| provider.instance_id.clone())
                .collect::<Vec<_>>();
            let provider_instance_id = match matching_provider_ids.as_slice() {
                [provider_instance_id] => provider_instance_id.clone(),
                [] => {
                    let provider_instance_id = unique_provider_instance_id(catalog);
                    catalog.provider_instances.push(ProviderInstance {
                        instance_id: provider_instance_id.clone(),
                        runtime_id: runtime_id.to_string(),
                        display_name: display_name.to_string(),
                        readiness: ProviderReadiness::Ready,
                        readiness_reason: None,
                        continuation_group_id: runtime_id.to_string(),
                        models: Vec::new(),
                        capabilities: RuntimeCapabilitiesV1::all_unknown(),
                    });
                    provider_instance_id
                }
                _ => return Err(anyhow!("provider instance selection is ambiguous")),
            };

            let thread_id = unique_thread_id(catalog);
            let provider_session_id = unique_provider_session_id(catalog);
            let route_handle = unique_route_handle(catalog);
            catalog.route_handles.push(RouteHandleRecord {
                route_handle: route_handle.clone(),
                thread_id: thread_id.clone(),
                created_at_ms: now_ms,
                expires_at_ms: None,
            });
            catalog.threads.push(ThreadRecord {
                summary: ThreadSummary {
                    thread_id: thread_id.clone(),
                    host_id: catalog.host_id.clone(),
                    project_id: None,
                    working_copy_id: None,
                    runtime_id: runtime_id.to_string(),
                    provider_instance_id: provider_instance_id.clone(),
                    title: "New thread".to_string(),
                    status: ThreadStatus::Running,
                    attention: AttentionState::None,
                    updated_at_ms: now_ms,
                    route_handle,
                },
                created_at_ms: now_ms,
                linked_parent_thread_id: None,
                archived_at_ms: None,
            });
            catalog.provider_sessions.push(ProviderSessionSummary {
                provider_session_id: provider_session_id.clone(),
                thread_id: thread_id.clone(),
                provider_instance_id: provider_instance_id.clone(),
                lifecycle: ProviderSessionLifecycle::Connected,
                resumable_session_id: Some(provider_thread_id.to_string()),
                updated_at_ms: now_ms,
            });
            Ok((
                ProviderThreadBinding {
                    thread_id,
                    provider_session_id,
                    provider_instance_id,
                    runtime_id: runtime_id.to_string(),
                    provider_thread_id: provider_thread_id.to_string(),
                },
                true,
            ))
        })
    }

    pub fn resolve_provider_thread(
        &self,
        thread_id: &ThreadId,
    ) -> anyhow::Result<Option<ProviderThreadBinding>> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bindings = state
            .provider_sessions
            .iter()
            .filter(|session| session.thread_id == *thread_id)
            .filter(|session| session.resumable_session_id.is_some())
            .map(|session| provider_thread_binding(&state, session))
            .collect::<anyhow::Result<Vec<_>>>()?;
        match bindings.as_slice() {
            [] => Ok(None),
            [binding] => Ok(Some(binding.clone())),
            _ => Err(anyhow!("Host Thread provider binding is ambiguous")),
        }
    }

    /// Reserve one external provider mutation exactly once.
    ///
    /// A new durable reservation returns `Execute`. Replays never execute:
    /// a prior reservation remains `Reserved`, a dispatch fence becomes
    /// `OutcomeUnknown`, and a completed intent returns its stored receipt.
    pub fn prepare_send_message_intent(
        &self,
        intent_id: &str,
        origin_credential_id: &str,
        request_fingerprint: &str,
        thread_id: ThreadId,
        now_ms: i64,
    ) -> anyhow::Result<WorkIntentPreparation> {
        let commit = self.transact_maybe(|catalog| {
            if let Some(existing) = catalog
                .work_intents
                .iter()
                .find(|record| record.intent_id == intent_id)
            {
                if existing.origin_credential_id != origin_credential_id
                    || existing.kind != WorkIntentKind::SendMessage
                    || existing.request_fingerprint != request_fingerprint
                    || existing.thread_id.as_ref() != Some(&thread_id)
                {
                    return Err(anyhow!("work intent conflicts with its durable receipt"));
                }
                return Ok(((existing.clone(), false), false));
            }
            let record = WorkIntentRecord {
                intent_id: intent_id.to_string(),
                origin_credential_id: origin_credential_id.to_string(),
                kind: WorkIntentKind::SendMessage,
                request_fingerprint: request_fingerprint.to_string(),
                state: WorkIntentState::Reserved,
                thread_id: Some(thread_id),
                turn_id: None,
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
            };
            catalog.work_intents.push(record.clone());
            Ok(((record, true), true))
        })?;
        let (record, inserted) = commit.value().clone();
        if matches!(commit, CatalogCommit::CommittedUnknown { .. }) {
            return Ok(WorkIntentPreparation::OutcomeUnknown(record));
        }
        if inserted {
            return Ok(WorkIntentPreparation::Execute(record));
        }
        Ok(match record.state {
            WorkIntentState::Reserved => WorkIntentPreparation::Reserved(record),
            WorkIntentState::Dispatching => WorkIntentPreparation::OutcomeUnknown(record),
            WorkIntentState::Succeeded => WorkIntentPreparation::Succeeded(record),
        })
    }

    /// Fence a reserved intent immediately before the external provider call.
    /// A replay of this state must reconcile Host history instead of sending.
    pub fn mark_work_intent_dispatching(
        &self,
        intent_id: &str,
        origin_credential_id: &str,
        request_fingerprint: &str,
        thread_id: &ThreadId,
        now_ms: i64,
    ) -> anyhow::Result<WorkIntentPreparation> {
        let commit = self.transact_maybe(|catalog| {
            let record = catalog
                .work_intents
                .iter_mut()
                .find(|record| record.intent_id == intent_id)
                .ok_or_else(|| anyhow!("work intent is unavailable"))?;
            if record.origin_credential_id != origin_credential_id
                || record.request_fingerprint != request_fingerprint
                || record.thread_id.as_ref() != Some(thread_id)
            {
                return Err(anyhow!("work intent conflicts with its durable receipt"));
            }
            let transitioned = match record.state {
                WorkIntentState::Reserved => {
                    record.state = WorkIntentState::Dispatching;
                    record.updated_at_ms = now_ms;
                    true
                }
                WorkIntentState::Dispatching | WorkIntentState::Succeeded => false,
            };
            Ok(((record.clone(), transitioned), transitioned))
        })?;
        let (record, transitioned) = commit.value().clone();
        Ok(match (commit, record.state, transitioned) {
            (CatalogCommit::Durable(_), WorkIntentState::Dispatching, true) => {
                WorkIntentPreparation::Execute(record)
            }
            (_, WorkIntentState::Succeeded, _) => WorkIntentPreparation::Succeeded(record),
            _ => WorkIntentPreparation::OutcomeUnknown(record),
        })
    }

    pub fn mark_work_intent_succeeded(
        &self,
        intent_id: &str,
        origin_credential_id: &str,
        request_fingerprint: &str,
        thread_id: &ThreadId,
        now_ms: i64,
    ) -> anyhow::Result<WorkIntentPreparation> {
        let commit = self.transact_maybe(|catalog| {
            let intent_index = catalog
                .work_intents
                .iter()
                .position(|record| record.intent_id == intent_id)
                .ok_or_else(|| anyhow!("work intent is unavailable"))?;
            let record = &catalog.work_intents[intent_index];
            if record.kind != WorkIntentKind::SendMessage
                || record.origin_credential_id != origin_credential_id
                || record.request_fingerprint != request_fingerprint
                || record.thread_id.as_ref() != Some(thread_id)
                || !matches!(
                    record.state,
                    WorkIntentState::Dispatching | WorkIntentState::Succeeded
                )
            {
                return Err(anyhow!(
                    "work intent success conflicts with its durable receipt"
                ));
            }
            if record.state == WorkIntentState::Succeeded {
                return Ok(((record.clone(), false), false));
            }
            let turn_id = unique_turn_id(catalog);
            catalog.turns.push(TurnSummary {
                turn_id: turn_id.clone(),
                thread_id: thread_id.clone(),
                lifecycle: TurnLifecycle::Running,
                started_at_ms: now_ms,
                completed_at_ms: None,
                checkpoint_id: None,
            });
            let record = &mut catalog.work_intents[intent_index];
            record.state = WorkIntentState::Succeeded;
            record.turn_id = Some(turn_id);
            record.updated_at_ms = now_ms;
            Ok(((record.clone(), true), true))
        })?;
        let (record, _) = commit.value().clone();
        Ok(match commit {
            CatalogCommit::Durable(_) => WorkIntentPreparation::Succeeded(record),
            CatalogCommit::CommittedUnknown { .. } => WorkIntentPreparation::OutcomeUnknown(record),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEntry {
    generation: u64,
    sha256: String,
    catalog: HostCatalogV1,
}

fn load_snapshot(path: &Path) -> anyhow::Result<Option<HostCatalogV1>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let state: HostCatalogV1 =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    state
        .validate()
        .with_context(|| format!("validating {}", path.display()))?;
    Ok(Some(state))
}

fn recover_from_journal(path: &Path) -> anyhow::Result<Option<HostCatalogV1>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("opening {}", path.display())),
    };
    let mut recovered = None;
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else { continue };
        let Ok(entry) = serde_json::from_str::<JournalEntry>(&line) else {
            continue;
        };
        if entry.generation != entry.catalog.generation
            || catalog_checksum(&entry.catalog)? != entry.sha256
            || entry.catalog.validate().is_err()
        {
            continue;
        }
        if recovered
            .as_ref()
            .is_none_or(|current: &HostCatalogV1| current.generation < entry.generation)
        {
            recovered = Some(entry.catalog);
        }
    }
    Ok(recovered)
}

fn append_journal(path: &Path, state: &HostCatalogV1) -> anyhow::Result<()> {
    let entry = JournalEntry {
        generation: state.generation,
        sha256: catalog_checksum(state)?,
        catalog: state.clone(),
    };
    let mut bytes = serde_json::to_vec(&entry).context("serializing Host catalog journal")?;
    bytes.push(b'\n');
    let journal_existed = path.exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    set_mode_0600(path)?;
    file.write_all(&bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    if !journal_existed && let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("syncing catalog directory {}", parent.display()))?;
    }
    Ok(())
}

fn compact_journal_if_needed(path: &Path, state: &HostCatalogV1) -> anyhow::Result<()> {
    if fs::metadata(path).map_or(0, |metadata| metadata.len()) <= JOURNAL_COMPACT_BYTES {
        return Ok(());
    }
    let entry = JournalEntry {
        generation: state.generation,
        sha256: catalog_checksum(state)?,
        catalog: state.clone(),
    };
    let mut bytes = serde_json::to_vec(&entry).context("serializing compacted Host journal")?;
    bytes.push(b'\n');
    write_atomic(path, &bytes)
}

fn persist_snapshot(path: &Path, state: &HostCatalogV1) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(state).context("serializing Host catalog")?;
    write_atomic(path, &bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .with_context(|| format!("opening {}", tmp.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("writing {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing {}", tmp.display()))?;
    }
    set_mode_0600(&tmp)?;
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    set_mode_0600(path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|file| file.sync_all())
            .with_context(|| format!("syncing catalog directory {}", parent.display()))?;
    }
    Ok(())
}

fn catalog_checksum(state: &HostCatalogV1) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(state).context("serializing Host catalog checksum")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn provider_thread_binding(
    catalog: &HostCatalogV1,
    session: &ProviderSessionSummary,
) -> anyhow::Result<ProviderThreadBinding> {
    let provider = catalog
        .provider_instances
        .iter()
        .find(|provider| provider.instance_id == session.provider_instance_id)
        .ok_or_else(|| anyhow!("provider Thread binding has no provider instance"))?;
    let provider_thread_id = session
        .resumable_session_id
        .clone()
        .ok_or_else(|| anyhow!("provider Thread binding is not resumable"))?;
    Ok(ProviderThreadBinding {
        thread_id: session.thread_id.clone(),
        provider_session_id: session.provider_session_id.clone(),
        provider_instance_id: session.provider_instance_id.clone(),
        runtime_id: provider.runtime_id.clone(),
        provider_thread_id,
    })
}

fn validate_bounded_label(kind: &str, value: &str) -> anyhow::Result<()> {
    if value.trim().is_empty()
        || value.len() > MAX_DISPLAY_LABEL_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(anyhow!("{kind} is invalid"));
    }
    Ok(())
}

fn random_opaque_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    debug_assert_eq!(encoded.len(), OPAQUE_ID_LENGTH);
    encoded
}

fn random_host_id() -> HostId {
    HostId(random_opaque_id())
}

fn unique_provider_instance_id(catalog: &HostCatalogV1) -> ProviderInstanceId {
    loop {
        let candidate = ProviderInstanceId(random_opaque_id());
        if catalog
            .provider_instances
            .iter()
            .all(|provider| provider.instance_id != candidate)
        {
            return candidate;
        }
    }
}

fn unique_thread_id(catalog: &HostCatalogV1) -> ThreadId {
    loop {
        let candidate = ThreadId(random_opaque_id());
        if catalog
            .threads
            .iter()
            .all(|thread| thread.summary.thread_id != candidate)
        {
            return candidate;
        }
    }
}

fn unique_provider_session_id(catalog: &HostCatalogV1) -> ProviderSessionId {
    loop {
        let candidate = ProviderSessionId(random_opaque_id());
        if catalog
            .provider_sessions
            .iter()
            .all(|session| session.provider_session_id != candidate)
        {
            return candidate;
        }
    }
}

fn unique_route_handle(catalog: &HostCatalogV1) -> RouteHandle {
    loop {
        let candidate = RouteHandle(random_opaque_id());
        if catalog
            .route_handles
            .iter()
            .all(|route| route.route_handle != candidate)
        {
            return candidate;
        }
    }
}

fn unique_turn_id(catalog: &HostCatalogV1) -> TurnId {
    loop {
        let candidate = TurnId(random_opaque_id());
        if catalog.turns.iter().all(|turn| turn.turn_id != candidate) {
            return candidate;
        }
    }
}

#[cfg(unix)]
fn set_mode_0600(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))
}

#[cfg(not(unix))]
fn set_mode_0600(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_mode_0700(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", path.display()))
}

#[cfg(not(unix))]
fn set_mode_0700(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use remora_bridge_core::command_center::{
        AttentionState, ProviderInstance, ProviderInstanceId, ProviderReadiness, RouteHandle,
        RouteHandleRecord, RuntimeCapabilitiesV1, ThreadRecord, ThreadStatus, ThreadSummary,
    };

    fn open(root: &Path) -> HostCatalogStore {
        HostCatalogStore::open(
            root.join("catalog.json"),
            root.join("catalog.journal.jsonl"),
            HostCapabilitiesV1::all_unknown(2, "0.1.0"),
        )
        .expect("open catalog")
    }

    fn seed_scratch_thread(store: &HostCatalogStore) -> ThreadId {
        let thread_id = ThreadId("efghijklmnopqrstuvwxyz".to_string());
        let route_handle = RouteHandle("ijklmnopqrstuvwxyzabcd".to_string());
        let provider_instance_id = ProviderInstanceId("bcdefghijklmnopqrstuvw".to_string());
        store
            .transact(|catalog| {
                catalog.provider_instances.push(ProviderInstance {
                    instance_id: provider_instance_id.clone(),
                    runtime_id: "codex".to_string(),
                    display_name: "Codex".to_string(),
                    readiness: ProviderReadiness::Ready,
                    readiness_reason: None,
                    continuation_group_id: "codex-default".to_string(),
                    models: Vec::new(),
                    capabilities: RuntimeCapabilitiesV1::all_unknown(),
                });
                catalog.route_handles.push(RouteHandleRecord {
                    route_handle: route_handle.clone(),
                    thread_id: thread_id.clone(),
                    created_at_ms: 1,
                    expires_at_ms: None,
                });
                catalog.threads.push(ThreadRecord {
                    summary: ThreadSummary {
                        thread_id: thread_id.clone(),
                        host_id: catalog.host_id.clone(),
                        project_id: None,
                        working_copy_id: None,
                        runtime_id: "codex".to_string(),
                        provider_instance_id,
                        title: "Scratch".to_string(),
                        status: ThreadStatus::Running,
                        attention: AttentionState::None,
                        updated_at_ms: 1,
                        route_handle,
                    },
                    created_at_ms: 1,
                    linked_parent_thread_id: None,
                    archived_at_ms: None,
                });
                Ok(())
            })
            .expect("seed Thread");
        thread_id
    }

    #[test]
    fn new_catalog_uses_stable_random_opaque_host_id() {
        let root = tempfile::tempdir().expect("tempdir");
        let first = open(root.path()).snapshot();
        let second = open(root.path()).snapshot();
        assert_eq!(first.host_id, second.host_id);
        assert_eq!(first.host_id.as_str().len(), OPAQUE_ID_LENGTH);
    }

    #[test]
    fn transaction_is_durable_and_increments_generation_once() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = open(root.path());
        store
            .transact(|state| {
                state.host_capabilities.project_registration =
                    remora_bridge_core::command_center::FeatureAvailability::available();
                Ok(())
            })
            .expect("commit");
        assert_eq!(store.snapshot().generation, 1);
        let reopened = open(root.path()).snapshot();
        assert_eq!(reopened.generation, 1);
        assert_eq!(
            reopened.host_capabilities.project_registration.state,
            remora_bridge_core::command_center::AvailabilityState::Available
        );
    }

    #[test]
    fn provider_thread_binding_is_idempotent_durable_and_projectless() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = open(root.path());
        let first = store
            .bind_provider_thread("codex", "Codex", "provider-thread-1", 10)
            .expect("bind provider Thread")
            .value()
            .clone();
        let snapshot = store.snapshot();
        assert_eq!(snapshot.generation, 1);
        assert_eq!(snapshot.provider_instances.len(), 1);
        assert_eq!(snapshot.threads.len(), 1);
        assert_eq!(snapshot.provider_sessions.len(), 1);
        assert_eq!(snapshot.route_handles.len(), 1);
        assert!(snapshot.projects.is_empty());
        assert!(snapshot.working_copies.is_empty());
        assert!(snapshot.threads[0].summary.project_id.is_none());
        assert!(snapshot.threads[0].summary.working_copy_id.is_none());
        assert_eq!(snapshot.threads[0].summary.title, "New thread");
        assert_eq!(first.thread_id.as_str().len(), OPAQUE_ID_LENGTH);
        assert_eq!(first.provider_session_id.as_str().len(), OPAQUE_ID_LENGTH);
        assert_eq!(first.provider_instance_id.as_str().len(), OPAQUE_ID_LENGTH);

        let replay = store
            .bind_provider_thread("codex", "Renamed Codex", "provider-thread-1", 11)
            .expect("replay provider Thread binding")
            .value()
            .clone();
        assert_eq!(replay, first);
        assert_eq!(store.snapshot().generation, 1);

        drop(store);
        let reopened = open(root.path());
        assert_eq!(
            reopened
                .resolve_provider_thread(&first.thread_id)
                .expect("resolve provider Thread"),
            Some(first)
        );
    }

    #[test]
    fn provider_thread_binding_replays_before_named_instance_ambiguity() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = open(root.path());
        let first = store
            .bind_provider_thread("codex", "Codex", "provider-thread-1", 10)
            .expect("bind provider Thread")
            .value()
            .clone();
        store
            .transact(|catalog| {
                catalog.provider_instances.push(ProviderInstance {
                    instance_id: ProviderInstanceId("lmnopqrstuvwxyzabcdefg".to_string()),
                    runtime_id: "codex".to_string(),
                    display_name: "Codex Work".to_string(),
                    readiness: ProviderReadiness::Ready,
                    readiness_reason: None,
                    continuation_group_id: "codex-work".to_string(),
                    models: Vec::new(),
                    capabilities: RuntimeCapabilitiesV1::all_unknown(),
                });
                Ok(())
            })
            .expect("add named provider instance");

        let replay = store
            .bind_provider_thread("codex", "Codex", "provider-thread-1", 11)
            .expect("resolve existing provider Thread")
            .value()
            .clone();
        assert_eq!(replay, first);
        assert!(
            store
                .bind_provider_thread("codex", "Codex", "provider-thread-2", 12)
                .expect_err("new binding requires explicit named instance")
                .to_string()
                .contains("provider instance selection is ambiguous")
        );
    }

    #[test]
    fn provider_thread_binding_rejects_unbounded_or_control_text() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = open(root.path());
        assert!(
            store
                .bind_provider_thread("codex\n", "Codex", "provider-thread-1", 1)
                .is_err()
        );
        assert!(
            store
                .bind_provider_thread(
                    "codex",
                    "Codex",
                    &"x".repeat(MAX_DISPLAY_LABEL_BYTES + 1),
                    1,
                )
                .is_err()
        );
        assert!(
            store
                .bind_provider_thread("codex", "Codex", "provider-thread-1", -1)
                .is_err()
        );
        assert_eq!(store.snapshot().generation, 0);
    }

    #[test]
    fn corrupt_snapshot_recovers_latest_checksum_valid_journal_entry() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = open(root.path());
        store.transact(|_| Ok(())).expect("commit");
        fs::write(root.path().join("catalog.json"), b"not json").expect("corrupt snapshot");

        let recovered = open(root.path()).snapshot();
        assert_eq!(recovered.generation, 1);
        let reparsed = load_snapshot(&root.path().join("catalog.json"))
            .expect("repaired snapshot")
            .expect("snapshot exists");
        assert_eq!(reparsed.generation, 1);
    }

    #[test]
    fn newer_journal_entry_repairs_an_older_valid_snapshot() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = open(root.path());
        let generation_zero = store.snapshot();
        store.transact(|_| Ok(())).expect("commit");
        persist_snapshot(&root.path().join("catalog.json"), &generation_zero)
            .expect("simulate crash before snapshot replacement");

        let recovered = open(root.path()).snapshot();
        assert_eq!(recovered.generation, 1);
    }

    #[test]
    fn invalid_mutation_never_reaches_disk() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = open(root.path());
        let error = store
            .transact(|state| {
                state.host_id = HostId("not-an-opaque-id".to_string());
                Ok(())
            })
            .expect_err("invalid mutation must fail");
        assert!(error.to_string().contains("invalid Host catalog mutation"));
        assert_eq!(open(root.path()).snapshot().generation, 0);
    }

    #[test]
    fn journal_commit_advances_live_state_when_snapshot_mirror_fails() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = open(root.path());
        fs::create_dir(root.path().join("catalog.tmp")).expect("block snapshot replacement");

        let commit = store
            .transact(|state| {
                state.host_capabilities.project_registration =
                    remora_bridge_core::command_center::FeatureAvailability::available();
                Ok(())
            })
            .expect("journal commit");
        assert!(matches!(commit, CatalogCommit::CommittedUnknown { .. }));
        assert_eq!(store.snapshot().generation, 1);
        assert_eq!(
            store
                .snapshot()
                .host_capabilities
                .project_registration
                .state,
            remora_bridge_core::command_center::AvailabilityState::Available
        );

        fs::remove_dir(root.path().join("catalog.tmp")).expect("unblock snapshot replacement");
        let recovered = open(root.path()).snapshot();
        assert_eq!(recovered.generation, 1);
        assert_eq!(
            recovered.host_capabilities.project_registration.state,
            remora_bridge_core::command_center::AvailabilityState::Available
        );
    }

    #[test]
    fn send_message_intent_executes_once_and_replays_durable_receipt() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = open(root.path());
        let thread_id = seed_scratch_thread(&store);
        let generation = store.snapshot().generation;
        let fingerprint = "a".repeat(64);

        let prepared = store
            .prepare_send_message_intent(
                "device-intent-1",
                "jklmnopqrstuvwxyzabcde",
                &fingerprint,
                thread_id.clone(),
                2,
            )
            .expect("reserve intent");
        assert!(matches!(prepared, WorkIntentPreparation::Execute(_)));
        assert_eq!(store.snapshot().generation, generation + 1);

        let replay = store
            .prepare_send_message_intent(
                "device-intent-1",
                "jklmnopqrstuvwxyzabcde",
                &fingerprint,
                thread_id.clone(),
                3,
            )
            .expect("replay reservation");
        assert!(matches!(replay, WorkIntentPreparation::Reserved(_)));
        assert_eq!(store.snapshot().generation, generation + 1);

        assert!(
            store
                .prepare_send_message_intent(
                    "device-intent-1",
                    "jklmnopqrstuvwxyzabcde",
                    &"b".repeat(64),
                    thread_id.clone(),
                    3,
                )
                .is_err()
        );

        let dispatch = store
            .mark_work_intent_dispatching(
                "device-intent-1",
                "jklmnopqrstuvwxyzabcde",
                &fingerprint,
                &thread_id,
                3,
            )
            .expect("fence dispatch");
        assert!(matches!(dispatch, WorkIntentPreparation::Execute(_)));
        let generation = store.snapshot().generation;
        let replay = store
            .mark_work_intent_dispatching(
                "device-intent-1",
                "jklmnopqrstuvwxyzabcde",
                &fingerprint,
                &thread_id,
                4,
            )
            .expect("replay dispatch");
        assert!(matches!(replay, WorkIntentPreparation::OutcomeUnknown(_)));
        assert_eq!(store.snapshot().generation, generation);

        let completed = store
            .mark_work_intent_succeeded(
                "device-intent-1",
                "jklmnopqrstuvwxyzabcde",
                &fingerprint,
                &thread_id,
                4,
            )
            .expect("store success receipt");
        assert!(matches!(completed, WorkIntentPreparation::Succeeded(_)));

        let reopened = open(root.path());
        let replay = reopened
            .prepare_send_message_intent(
                "device-intent-1",
                "jklmnopqrstuvwxyzabcde",
                &fingerprint,
                ThreadId("efghijklmnopqrstuvwxyz".to_string()),
                5,
            )
            .expect("replay completed receipt");
        assert!(matches!(replay, WorkIntentPreparation::Succeeded(_)));
    }

    #[test]
    fn ambiguous_dispatch_commit_never_reexecutes_after_restart() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = open(root.path());
        let thread_id = seed_scratch_thread(&store);
        let fingerprint = "a".repeat(64);
        store
            .prepare_send_message_intent(
                "device-intent-1",
                "jklmnopqrstuvwxyzabcde",
                &fingerprint,
                thread_id.clone(),
                2,
            )
            .expect("reserve intent");
        fs::create_dir(root.path().join("catalog.tmp")).expect("block snapshot replacement");

        let dispatch = store
            .mark_work_intent_dispatching(
                "device-intent-1",
                "jklmnopqrstuvwxyzabcde",
                &fingerprint,
                &thread_id,
                3,
            )
            .expect("journal dispatch fence");
        assert!(matches!(dispatch, WorkIntentPreparation::OutcomeUnknown(_)));

        fs::remove_dir(root.path().join("catalog.tmp")).expect("unblock snapshot replacement");
        let reopened = open(root.path());
        let replay = reopened
            .prepare_send_message_intent(
                "device-intent-1",
                "jklmnopqrstuvwxyzabcde",
                &fingerprint,
                thread_id,
                4,
            )
            .expect("replay ambiguous intent");
        assert!(matches!(replay, WorkIntentPreparation::OutcomeUnknown(_)));
    }
}
