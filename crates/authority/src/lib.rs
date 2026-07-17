//! Durable Authority Store: crash-safe, cross-process one-use consumption.
//!
//! RFC 0002 requires that Capability V2 validation and consumption be a
//! single atomic operation that survives restarts and concurrent processes,
//! and that an unavailable store denies execution. This crate implements the
//! minimal durable core of that requirement for three kinds of authority:
//!
//! - one-use capability tokens (`consume_token`);
//! - one-use RFC 0003 approvals (`consume_approval`);
//! - idempotency keys bound to an invocation fingerprint
//!   (`bind_idempotency`), where re-presenting the same fingerprint is a
//!   replay and a different fingerprint is a conflict.
//!
//! ## Atomicity and durability
//!
//! A claim is a filesystem hard link into a content-addressed slot:
//! the record content is first written to an exclusive temporary file and
//! flushed, then `hard_link` publishes it under the authority id. Both POSIX
//! and Windows guarantee that linking to an existing name fails, so exactly
//! one process wins a race, and the winning record is always complete before
//! it becomes visible. Directories are flushed on Unix after publication.
//!
//! ## Honest limits
//!
//! Consumption is recorded before execution, so a crash between claim and
//! execution burns the authority without running anything — that is the
//! fail-closed direction and re-issuance is the recovery path. Expired
//! records can be purged; replaying a purged id is denied by the token or
//! approval expiry checks, never by this store. This store does not make
//! external effects safe by itself: crash-safe audit intent ordering and
//! reviewed host interfaces remain separate RFC 0002 requirements.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

const TOKENS_DIR: &str = "tokens";
const APPROVALS_DIR: &str = "approvals";
const IDEMPOTENCY_DIR: &str = "idempotency";
const MAX_RECORD_BYTES: u64 = 4 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthorityError {
    #[error("authority was already consumed")]
    AlreadyConsumed,
    #[error("idempotency key was already consumed for the same invocation")]
    IdempotencyReplay,
    #[error("idempotency key was consumed for a different invocation")]
    IdempotencyConflict,
    #[error("authority record is invalid or corrupt")]
    CorruptRecord,
    #[error("authority store unavailable: {0}")]
    Unavailable(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthorityRecord {
    kind: String,
    fingerprint_hex: Option<String>,
    consumed_at_unix: i64,
    expires_at_unix: i64,
}

/// File-backed durable authority store. Every instance operating on the same
/// directory — in this process or another — observes the same consumption
/// state.
#[derive(Debug)]
pub struct AuthorityStore {
    tokens: PathBuf,
    approvals: PathBuf,
    idempotency: PathBuf,
}

impl AuthorityStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, AuthorityError> {
        let root = root.as_ref();
        let tokens = root.join(TOKENS_DIR);
        let approvals = root.join(APPROVALS_DIR);
        let idempotency = root.join(IDEMPOTENCY_DIR);
        for directory in [&tokens, &approvals, &idempotency] {
            std::fs::create_dir_all(directory).map_err(unavailable)?;
        }
        Ok(Self {
            tokens,
            approvals,
            idempotency,
        })
    }

    /// Atomically consume a one-use token. Exactly one caller across all
    /// processes ever succeeds for a given id.
    pub fn consume_token(
        &self,
        token_id: Uuid,
        now_unix: i64,
        expires_at_unix: i64,
    ) -> Result<(), AuthorityError> {
        self.claim(
            &self.tokens,
            token_id,
            AuthorityRecord {
                kind: "token".into(),
                fingerprint_hex: None,
                consumed_at_unix: now_unix,
                expires_at_unix,
            },
        )
        .map_err(|error| match error {
            ClaimError::Exists(_) => AuthorityError::AlreadyConsumed,
            ClaimError::Store(store_error) => store_error,
        })
    }

    /// Atomically consume a one-use RFC 0003 approval id.
    pub fn consume_approval(
        &self,
        approval_id: Uuid,
        now_unix: i64,
        expires_at_unix: i64,
    ) -> Result<(), AuthorityError> {
        self.claim(
            &self.approvals,
            approval_id,
            AuthorityRecord {
                kind: "approval".into(),
                fingerprint_hex: None,
                consumed_at_unix: now_unix,
                expires_at_unix,
            },
        )
        .map_err(|error| match error {
            ClaimError::Exists(_) => AuthorityError::AlreadyConsumed,
            ClaimError::Store(store_error) => store_error,
        })
    }

    /// Atomically bind an idempotency key to an invocation fingerprint.
    /// A second binding with the same fingerprint is a replay; with a
    /// different fingerprint it is a conflict.
    pub fn bind_idempotency(
        &self,
        key: Uuid,
        fingerprint: &[u8; 32],
        now_unix: i64,
        expires_at_unix: i64,
    ) -> Result<(), AuthorityError> {
        let fingerprint_hex = hex::encode(fingerprint);
        match self.claim(
            &self.idempotency,
            key,
            AuthorityRecord {
                kind: "idempotency".into(),
                fingerprint_hex: Some(fingerprint_hex.clone()),
                consumed_at_unix: now_unix,
                expires_at_unix,
            },
        ) {
            Ok(()) => Ok(()),
            Err(ClaimError::Exists(existing)) => match existing.fingerprint_hex.as_deref() {
                Some(existing_hex) if existing_hex == fingerprint_hex => {
                    Err(AuthorityError::IdempotencyReplay)
                }
                Some(_) => Err(AuthorityError::IdempotencyConflict),
                None => Err(AuthorityError::CorruptRecord),
            },
            Err(ClaimError::Store(store_error)) => Err(store_error),
        }
    }

    /// Remove records whose expiry has passed. Safe by construction: a
    /// purged token or approval is independently rejected as expired by the
    /// validator's temporal checks, so purging can never re-enable replay of
    /// a still-valid authority.
    pub fn purge_expired(&self, now_unix: i64) -> Result<usize, AuthorityError> {
        let mut removed = 0;
        for directory in [&self.tokens, &self.approvals, &self.idempotency] {
            let entries = std::fs::read_dir(directory).map_err(unavailable)?;
            for entry in entries.filter_map(|entry| entry.ok()) {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if name.starts_with("tmp-") {
                    // Orphan temporaries from a crashed claim are never
                    // authoritative; collect them opportunistically.
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                if let Ok(record) = read_record(&path) {
                    if record.expires_at_unix <= now_unix && std::fs::remove_file(&path).is_ok() {
                        removed += 1;
                    }
                }
            }
        }
        Ok(removed)
    }

    fn claim(&self, directory: &Path, id: Uuid, record: AuthorityRecord) -> Result<(), ClaimError> {
        let final_path = directory.join(id.to_string());
        let temp_path = directory.join(format!("tmp-{}", Uuid::new_v4()));
        let bytes =
            serde_json::to_vec(&record).map_err(|error| ClaimError::Store(unavailable(error)))?;

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let write_result = (|| {
            let mut file = options.open(&temp_path).map_err(unavailable)?;
            file.write_all(&bytes).map_err(unavailable)?;
            file.sync_all().map_err(unavailable)?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&temp_path);
            return Err(ClaimError::Store(error));
        }

        // The atomic claim: linking to an existing name fails on every
        // supported platform, so exactly one racer publishes a record, and a
        // published record is always complete.
        match std::fs::hard_link(&temp_path, &final_path) {
            Ok(()) => {
                let _ = std::fs::remove_file(&temp_path);
                sync_directory(directory);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = std::fs::remove_file(&temp_path);
                let existing = read_record(&final_path)
                    .map_err(|_| ClaimError::Store(AuthorityError::CorruptRecord))?;
                Err(ClaimError::Exists(existing))
            }
            Err(error) => {
                let _ = std::fs::remove_file(&temp_path);
                Err(ClaimError::Store(unavailable(error)))
            }
        }
    }
}

enum ClaimError {
    Exists(AuthorityRecord),
    Store(AuthorityError),
}

fn read_record(path: &Path) -> Result<AuthorityRecord, AuthorityError> {
    let metadata = std::fs::symlink_metadata(path).map_err(unavailable)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_RECORD_BYTES {
        return Err(AuthorityError::CorruptRecord);
    }
    let bytes = std::fs::read(path).map_err(unavailable)?;
    serde_json::from_slice(&bytes).map_err(|_| AuthorityError::CorruptRecord)
}

#[cfg(unix)]
fn sync_directory(directory: &Path) {
    if let Ok(handle) = std::fs::File::open(directory) {
        let _ = handle.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) {}

fn unavailable(error: impl std::fmt::Display) -> AuthorityError {
    AuthorityError::Unavailable(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn one_use_consumption_survives_reopen() {
        let dir = tempdir().unwrap();
        let store = AuthorityStore::open(dir.path()).unwrap();
        let token = Uuid::new_v4();
        store.consume_token(token, NOW, NOW + 60).unwrap();
        assert_eq!(
            store.consume_token(token, NOW + 1, NOW + 60),
            Err(AuthorityError::AlreadyConsumed)
        );

        // "Restart": a fresh instance over the same directory still refuses.
        let reopened = AuthorityStore::open(dir.path()).unwrap();
        assert_eq!(
            reopened.consume_token(token, NOW + 2, NOW + 60),
            Err(AuthorityError::AlreadyConsumed)
        );
        assert_eq!(
            reopened.consume_approval(token, NOW, NOW + 60),
            Ok(()),
            "token and approval namespaces are separate"
        );
    }

    #[test]
    fn concurrent_racers_get_exactly_one_win() {
        let dir = tempdir().unwrap();
        let token = Uuid::new_v4();
        let root = dir.path().to_path_buf();
        let winners: usize = std::thread::scope(|scope| {
            (0..16)
                .map(|_| {
                    let root = root.clone();
                    scope.spawn(move || {
                        let store = AuthorityStore::open(&root).unwrap();
                        store.consume_token(token, NOW, NOW + 60).is_ok() as usize
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .sum()
        });
        assert_eq!(winners, 1);
    }

    #[test]
    fn idempotency_distinguishes_replay_from_conflict() {
        let dir = tempdir().unwrap();
        let store = AuthorityStore::open(dir.path()).unwrap();
        let key = Uuid::new_v4();
        let fingerprint_a = [0xAA_u8; 32];
        let fingerprint_b = [0xBB_u8; 32];

        store
            .bind_idempotency(key, &fingerprint_a, NOW, NOW + 60)
            .unwrap();
        assert_eq!(
            store.bind_idempotency(key, &fingerprint_a, NOW, NOW + 60),
            Err(AuthorityError::IdempotencyReplay)
        );
        // Across a "restart" a different fingerprint is a conflict.
        let reopened = AuthorityStore::open(dir.path()).unwrap();
        assert_eq!(
            reopened.bind_idempotency(key, &fingerprint_b, NOW, NOW + 60),
            Err(AuthorityError::IdempotencyConflict)
        );
    }

    #[test]
    fn unavailable_store_fails_closed() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("not-a-directory");
        std::fs::write(&file_path, b"occupied").unwrap();
        assert!(matches!(
            AuthorityStore::open(&file_path),
            Err(AuthorityError::Unavailable(_))
        ));
    }

    #[test]
    fn purge_removes_expired_and_keeps_live_records() {
        let dir = tempdir().unwrap();
        let store = AuthorityStore::open(dir.path()).unwrap();
        let expired = Uuid::new_v4();
        let live = Uuid::new_v4();
        store.consume_token(expired, NOW, NOW + 10).unwrap();
        store.consume_token(live, NOW, NOW + 1_000).unwrap();
        // Orphan temp file from a simulated crash is collected, never trusted.
        std::fs::write(dir.path().join("tokens").join("tmp-orphan"), b"junk").unwrap();

        let removed = store.purge_expired(NOW + 100).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(
            store.consume_token(live, NOW + 101, NOW + 1_000),
            Err(AuthorityError::AlreadyConsumed),
            "live record must survive the purge"
        );
        assert!(
            store.consume_token(expired, NOW + 101, NOW + 200).is_ok(),
            "purged ids are reclaimable; expiry checks upstream deny stale authorities"
        );
    }

    #[test]
    fn corrupt_records_fail_closed() {
        let dir = tempdir().unwrap();
        let store = AuthorityStore::open(dir.path()).unwrap();
        let key = Uuid::new_v4();
        std::fs::write(
            dir.path().join("idempotency").join(key.to_string()),
            b"garbage",
        )
        .unwrap();
        assert_eq!(
            store.bind_idempotency(key, &[0x01; 32], NOW, NOW + 60),
            Err(AuthorityError::CorruptRecord)
        );
    }
}
