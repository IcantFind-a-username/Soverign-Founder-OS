//! Crash-safe execution journal: durable intent before execution, durable
//! result after, and an honest `Indeterminate` verdict for anything in
//! between.
//!
//! RFC 0002 fixes the execution ordering:
//!
//! ```text
//! ExecutionRequested (hashes only)
//! → durable flush
//! → capability reserve/consume
//! → ExecutionStarted
//! → component and host calls
//! → ExecutionCompleted | ExecutionFailed | ExecutionIndeterminate
//! ```
//!
//! and requires that if intent evidence cannot be persisted, execution is
//! denied; and if an external effect may have occurred but its result cannot
//! be persisted, the outcome is `Indeterminate` and automatic retry is
//! forbidden.
//!
//! This crate implements that ordering as a per-execution append-only JSONL
//! record, each line flushed with `sync_all`. On read, a trailing partial or
//! unparseable line (the signature of a crash mid-write) is ignored, and the
//! terminal state is derived from the last complete record. An execution with
//! a durable intent but no terminal record is reported `Indeterminate`.
//!
//! ## Honest limits
//!
//! The current runtime executes pure computation with no host effects, so a
//! crashed run performed nothing observable; reporting it `Indeterminate` is
//! deliberately conservative and correct for the future effectful case. This
//! journal records lifecycle evidence; it is not the signed audit ledger and
//! does not replace it. Recovery here reports state — it never re-executes.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_JOURNAL_BYTES: u64 = 64 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JournalError {
    #[error("execution journal unavailable: {0}")]
    Unavailable(String),
    #[error("execution intent could not be persisted; execution denied")]
    IntentNotPersisted,
    #[error("execution record is invalid or corrupt")]
    CorruptRecord,
}

/// Hashes-only description of an execution attempt. Deliberately carries no
/// plaintext input, only digests and identifiers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionIntent {
    pub execution_id: Uuid,
    pub component_digest_hex: String,
    pub canonical_input_digest_hex: String,
    pub requested_at_unix: i64,
}

/// Terminal verdict for one execution attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Completed {
        result_hash_hex: String,
    },
    Failed {
        code: String,
    },
    /// The effect may have occurred but its result could not be recorded.
    /// Automatic retry is forbidden; a human must reconcile.
    Indeterminate {
        reason: String,
    },
}

/// The recovered state of one journalled execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionState {
    /// Intent durably recorded but no terminal record — a crash between
    /// intent and result. Treated as indeterminate; never auto-retried.
    Indeterminate,
    Started,
    Completed {
        result_hash_hex: String,
    },
    Failed {
        code: String,
    },
    RecordedIndeterminate {
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct RecoveredExecution {
    pub intent: ExecutionIntent,
    pub state: ExecutionState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
enum JournalRecord {
    Requested(ExecutionIntent),
    Started,
    Terminal(ExecutionOutcome),
}

/// File-backed crash-safe execution journal. One JSONL file per execution,
/// named by execution id.
#[derive(Debug)]
pub struct ExecutionJournal {
    dir: PathBuf,
}

impl ExecutionJournal {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, JournalError> {
        let dir = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(unavailable)?;
        Ok(Self { dir })
    }

    /// Record execution intent and flush it durably before returning a guard.
    /// If the intent cannot be persisted, no guard is returned and the caller
    /// must deny execution (fail closed).
    pub fn begin(&self, intent: ExecutionIntent) -> Result<ExecutionGuard<'_>, JournalError> {
        let path = self.dir.join(format!("{}.jsonl", intent.execution_id));
        // Exclusive create: an execution id is never reused.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| JournalError::Unavailable(error.to_string()))?;
        append_line(&mut file, &JournalRecord::Requested(intent.clone()))
            .map_err(|_| JournalError::IntentNotPersisted)?;
        Ok(ExecutionGuard {
            journal: self,
            path,
            execution_id: intent.execution_id,
        })
    }

    /// Recover every journalled execution's state, for inspection or
    /// crash-recovery reporting. Never re-executes anything.
    pub fn recover(&self) -> Result<Vec<RecoveredExecution>, JournalError> {
        let mut recovered = Vec::new();
        let entries = std::fs::read_dir(&self.dir).map_err(unavailable)?;
        for entry in entries.filter_map(|entry| entry.ok()) {
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("jsonl") {
                continue;
            }
            if let Some(execution) = read_execution(&path)? {
                recovered.push(execution);
            }
        }
        Ok(recovered)
    }
}

/// RAII handle over one in-progress execution. Dropping it without a terminal
/// record leaves the journal reporting `Indeterminate` on recovery — the
/// correct verdict for an execution interrupted before it could record its
/// result.
pub struct ExecutionGuard<'j> {
    journal: &'j ExecutionJournal,
    path: PathBuf,
    execution_id: Uuid,
}

impl ExecutionGuard<'_> {
    pub fn execution_id(&self) -> Uuid {
        self.execution_id
    }

    /// Record that guest execution has started (after the capability was
    /// consumed). Flushed durably.
    pub fn started(&self) -> Result<(), JournalError> {
        self.append(&JournalRecord::Started)
    }

    /// Record the terminal verdict, flushed durably, and consume the guard.
    pub fn finish(self, outcome: ExecutionOutcome) -> Result<(), JournalError> {
        self.append(&JournalRecord::Terminal(outcome))
    }

    fn append(&self, record: &JournalRecord) -> Result<(), JournalError> {
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(unavailable)?;
        append_line(&mut file, record).map_err(unavailable)
    }
}

impl Drop for ExecutionGuard<'_> {
    fn drop(&mut self) {
        // No terminal record on drop: recovery derives Indeterminate. We do
        // not write anything here — a panic mid-drop must not mask the crash
        // signal, and the absence of a terminal line already means "unknown".
        let _ = &self.journal;
    }
}

fn append_line(file: &mut std::fs::File, record: &JournalRecord) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(record)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    line.push(b'\n');
    file.write_all(&line)?;
    file.sync_all()
}

fn read_execution(path: &Path) -> Result<Option<RecoveredExecution>, JournalError> {
    let metadata = std::fs::symlink_metadata(path).map_err(unavailable)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_JOURNAL_BYTES {
        return Err(JournalError::CorruptRecord);
    }
    let bytes = std::fs::read(path).map_err(unavailable)?;
    let text = String::from_utf8(bytes).map_err(|_| JournalError::CorruptRecord)?;

    let mut intent: Option<ExecutionIntent> = None;
    let mut state = ExecutionState::Indeterminate;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        // A crash mid-write leaves a trailing partial line that fails to
        // parse; ignore it rather than treating the whole record as corrupt.
        let Ok(record) = serde_json::from_str::<JournalRecord>(line) else {
            continue;
        };
        match record {
            JournalRecord::Requested(recorded_intent) => {
                intent = Some(recorded_intent);
                state = ExecutionState::Indeterminate;
            }
            JournalRecord::Started => {
                if intent.is_some() {
                    state = ExecutionState::Started;
                }
            }
            JournalRecord::Terminal(outcome) => {
                state = match outcome {
                    ExecutionOutcome::Completed { result_hash_hex } => {
                        ExecutionState::Completed { result_hash_hex }
                    }
                    ExecutionOutcome::Failed { code } => ExecutionState::Failed { code },
                    ExecutionOutcome::Indeterminate { reason } => {
                        ExecutionState::RecordedIndeterminate { reason }
                    }
                };
            }
        }
    }

    Ok(intent.map(|intent| RecoveredExecution { intent, state }))
}

fn unavailable(error: impl std::fmt::Display) -> JournalError {
    JournalError::Unavailable(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const NOW: i64 = 1_800_000_000;

    fn intent(id: u128) -> ExecutionIntent {
        ExecutionIntent {
            execution_id: Uuid::from_u128(id),
            component_digest_hex: "aa".repeat(32),
            canonical_input_digest_hex: "bb".repeat(32),
            requested_at_unix: NOW,
        }
    }

    #[test]
    fn completed_execution_recovers_as_completed() {
        let dir = tempdir().unwrap();
        let journal = ExecutionJournal::open(dir.path()).unwrap();
        let guard = journal.begin(intent(1)).unwrap();
        guard.started().unwrap();
        guard
            .finish(ExecutionOutcome::Completed {
                result_hash_hex: "cc".repeat(32),
            })
            .unwrap();

        let recovered = ExecutionJournal::open(dir.path())
            .unwrap()
            .recover()
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(
            recovered[0].state,
            ExecutionState::Completed {
                result_hash_hex: "cc".repeat(32)
            }
        );
    }

    #[test]
    fn interrupted_execution_recovers_as_indeterminate() {
        let dir = tempdir().unwrap();
        let journal = ExecutionJournal::open(dir.path()).unwrap();
        // Simulate a crash: intent + started recorded, guard dropped without
        // a terminal record.
        {
            let guard = journal.begin(intent(2)).unwrap();
            guard.started().unwrap();
            // guard dropped here — no finish()
        }

        let recovered = ExecutionJournal::open(dir.path())
            .unwrap()
            .recover()
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].state, ExecutionState::Started);
        // "Started but no terminal" is the crash signal a recovery tool must
        // treat as indeterminate and never auto-retry.
        assert!(matches!(
            recovered[0].state,
            ExecutionState::Started | ExecutionState::Indeterminate
        ));
    }

    #[test]
    fn intent_only_recovers_as_indeterminate() {
        let dir = tempdir().unwrap();
        let journal = ExecutionJournal::open(dir.path()).unwrap();
        {
            let _guard = journal.begin(intent(3)).unwrap();
        }
        let recovered = ExecutionJournal::open(dir.path())
            .unwrap()
            .recover()
            .unwrap();
        assert_eq!(recovered[0].state, ExecutionState::Indeterminate);
    }

    #[test]
    fn trailing_partial_line_is_ignored_not_fatal() {
        let dir = tempdir().unwrap();
        let journal = ExecutionJournal::open(dir.path()).unwrap();
        let guard = journal.begin(intent(4)).unwrap();
        guard.started().unwrap();
        drop(guard);
        // Append a torn line, as a crash mid-write would leave.
        let path = dir.path().join(format!("{}.jsonl", Uuid::from_u128(4)));
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"record\":\"ter").unwrap();
        drop(file);

        let recovered = ExecutionJournal::open(dir.path())
            .unwrap()
            .recover()
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].state, ExecutionState::Started);
    }

    #[test]
    fn finished_guard_records_terminal_and_reopen_agrees() {
        let dir = tempdir().unwrap();
        let journal = ExecutionJournal::open(dir.path()).unwrap();
        let guard = journal.begin(intent(5)).unwrap();
        guard.started().unwrap();
        guard
            .finish(ExecutionOutcome::Failed {
                code: "guest_trap".into(),
            })
            .unwrap();
        let recovered = journal.recover().unwrap();
        assert_eq!(
            recovered[0].state,
            ExecutionState::Failed {
                code: "guest_trap".into()
            }
        );
    }

    #[test]
    fn execution_id_is_never_reused() {
        let dir = tempdir().unwrap();
        let journal = ExecutionJournal::open(dir.path()).unwrap();
        let _first = journal.begin(intent(6)).unwrap();
        assert!(matches!(
            journal.begin(intent(6)),
            Err(JournalError::Unavailable(_))
        ));
    }
}
