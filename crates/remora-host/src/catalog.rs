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
    HostCapabilitiesV1, HostCatalogV1, HostId, OPAQUE_ID_LENGTH,
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
    ) -> anyhow::Result<T> {
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
        let result = mutation(&mut next)?;
        next.generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("Host catalog generation exhausted"))?;
        state
            .validate_transition(&next)
            .context("rejecting invalid Host catalog mutation")?;

        append_journal(&self.journal_path, &next)?;
        persist_snapshot(&self.snapshot_path, &next)?;
        compact_journal_if_needed(&self.journal_path, &next)?;
        *state = next;
        Ok(result)
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

fn random_host_id() -> HostId {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    debug_assert_eq!(encoded.len(), OPAQUE_ID_LENGTH);
    HostId(encoded)
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

    fn open(root: &Path) -> HostCatalogStore {
        HostCatalogStore::open(
            root.join("catalog.json"),
            root.join("catalog.journal.jsonl"),
            HostCapabilitiesV1::all_unknown(2, "0.1.0"),
        )
        .expect("open catalog")
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
}
