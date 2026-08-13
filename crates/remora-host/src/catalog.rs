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
    HostCapabilitiesV1, HostCatalogV1, HostId, OPAQUE_ID_LENGTH, ThreadId, TurnId, TurnLifecycle,
    TurnSummary, WorkIntentKind, WorkIntentRecord, WorkIntentState,
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
