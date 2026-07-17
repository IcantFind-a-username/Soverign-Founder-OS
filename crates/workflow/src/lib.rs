//! Durable, resumable workflows: crash-safe checkpoints, deterministic
//! idempotency keys, and step replay that never repeats completed work.
//!
//! This is the Stage 3 foundation. A workflow is an ordered list of
//! deterministic steps. After each step completes, the runner atomically
//! rewrites a single checkpoint file (temp → flush → rename → directory
//! flush), so a crash leaves either the previous or the new checkpoint, never
//! a partial one. On resume — in the same process or another one over the same
//! durable directory — completed steps are skipped by replaying their
//! receipts, and only the remaining steps run.
//!
//! Each step's idempotency key is derived deterministically from the workflow
//! id, the step index, and the step name (UUID v5). Re-running a completed
//! workflow is a no-op that returns the same summary, and a step that already
//! has a receipt is never executed again — the property that makes external
//! effects safe to resume: the effectful step checks its idempotency key
//! before acting.
//!
//! ## Honest limits
//!
//! "Another node" here means another runner instance over the same durable
//! directory, exactly as the Authority Store demonstrates cross-process
//! consumption. True multi-machine failover (replication, leases,
//! split-brain prevention) is later work. Steps in this crate must be
//! deterministic and are expected to be pure or to guard their own effects by
//! idempotency key; the runner guarantees ordering and no-repeat, not
//! rollback of a partially applied effect.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const CHECKPOINT_FILE: &str = "checkpoint.json";
const MAX_CHECKPOINT_BYTES: u64 = 256 * 1024;
// Stable namespace for deterministic per-step idempotency keys.
const WORKFLOW_NAMESPACE: Uuid = Uuid::from_bytes([
    0x8f, 0x2a, 0x11, 0xd3, 0x4b, 0x5c, 0x47, 0x9e, 0xa1, 0x0c, 0x77, 0x21, 0x63, 0x0e, 0x0a, 0x0a,
]);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WorkflowError {
    #[error("workflow storage unavailable: {0}")]
    Unavailable(String),
    #[error("checkpoint is corrupt")]
    CorruptCheckpoint,
    #[error("checkpoint belongs to a different workflow")]
    WorkflowMismatch,
    #[error("checkpoint diverges from the declared steps: {0}")]
    StepDivergence(&'static str),
    #[error("step `{step}` failed: {reason}")]
    StepFailed { step: String, reason: String },
}

/// Immutable receipt for one completed step. `idempotency_key` is derived
/// deterministically; `output_digest_hex` binds the step's output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepReceipt {
    pub index: usize,
    pub name: String,
    pub idempotency_key: Uuid,
    pub output_digest_hex: String,
}

/// The durable state of one workflow run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub workflow_id: String,
    pub completed: Vec<StepReceipt>,
    pub done: bool,
}

impl Checkpoint {
    fn empty(workflow_id: &str) -> Self {
        Self {
            workflow_id: workflow_id.to_owned(),
            completed: Vec::new(),
            done: false,
        }
    }
}

/// Context passed to a step: the receipts of every step already completed.
pub struct StepContext<'a> {
    pub workflow_id: &'a str,
    pub prior: &'a [StepReceipt],
}

/// One deterministic step. `run` must be pure or must guard its own external
/// effect by `context`'s idempotency information; it returns the step's output
/// bytes, whose digest is recorded in the receipt.
pub trait WorkflowStep {
    fn name(&self) -> &str;
    fn run(&self, context: &StepContext<'_>) -> Result<Vec<u8>, String>;
}

/// Summary of a completed (or resumed-to-completion) workflow run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowSummary {
    pub workflow_id: String,
    pub receipts: Vec<StepReceipt>,
    /// Step indices that actually executed on this call (empty on a resume of
    /// an already-complete workflow).
    pub executed_now: Vec<usize>,
}

/// Runs and resumes one workflow against a durable checkpoint directory.
#[derive(Debug)]
pub struct WorkflowRunner {
    workflow_id: String,
    checkpoint_path: PathBuf,
    dir: PathBuf,
}

impl WorkflowRunner {
    pub fn open(
        dir: impl AsRef<Path>,
        workflow_id: impl Into<String>,
    ) -> Result<Self, WorkflowError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(unavailable)?;
        Ok(Self {
            workflow_id: workflow_id.into(),
            checkpoint_path: dir.join(CHECKPOINT_FILE),
            dir,
        })
    }

    /// Load the current checkpoint, or an empty one if the workflow has not
    /// started. A checkpoint for a different workflow id is rejected.
    pub fn checkpoint(&self) -> Result<Checkpoint, WorkflowError> {
        if !self.checkpoint_path.exists() {
            return Ok(Checkpoint::empty(&self.workflow_id));
        }
        let metadata = std::fs::symlink_metadata(&self.checkpoint_path).map_err(unavailable)?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_CHECKPOINT_BYTES {
            return Err(WorkflowError::CorruptCheckpoint);
        }
        let bytes = std::fs::read(&self.checkpoint_path).map_err(unavailable)?;
        let checkpoint: Checkpoint =
            serde_json::from_slice(&bytes).map_err(|_| WorkflowError::CorruptCheckpoint)?;
        if checkpoint.workflow_id != self.workflow_id {
            return Err(WorkflowError::WorkflowMismatch);
        }
        Ok(checkpoint)
    }

    /// Run the workflow to completion, resuming from the last checkpoint.
    /// Completed steps are replayed from their receipts, not re-executed.
    pub fn run(&self, steps: &[Box<dyn WorkflowStep>]) -> Result<WorkflowSummary, WorkflowError> {
        let mut checkpoint = self.checkpoint()?;

        // The declared steps must be a superset extension of what we already
        // completed: same names in the same positions. A divergence means the
        // workflow definition changed under a live checkpoint — fail closed.
        if checkpoint.completed.len() > steps.len() {
            return Err(WorkflowError::StepDivergence("fewer steps than completed"));
        }
        for receipt in &checkpoint.completed {
            let declared = steps
                .get(receipt.index)
                .ok_or(WorkflowError::StepDivergence("missing step index"))?;
            if declared.name() != receipt.name {
                return Err(WorkflowError::StepDivergence("step name changed"));
            }
        }

        let mut executed_now = Vec::new();
        for (index, step) in steps.iter().enumerate() {
            if index < checkpoint.completed.len() {
                continue; // Already completed: replay from receipt, do not run.
            }
            let context = StepContext {
                workflow_id: &self.workflow_id,
                prior: &checkpoint.completed,
            };
            let output = step
                .run(&context)
                .map_err(|reason| WorkflowError::StepFailed {
                    step: step.name().to_owned(),
                    reason,
                })?;
            checkpoint.completed.push(StepReceipt {
                index,
                name: step.name().to_owned(),
                idempotency_key: step_idempotency_key(&self.workflow_id, index, step.name()),
                output_digest_hex: hex::encode(Sha256::digest(&output)),
            });
            executed_now.push(index);
            // Durable checkpoint after every step: crash-safe resume point.
            self.persist(&checkpoint)?;
        }

        if !checkpoint.done {
            checkpoint.done = true;
            self.persist(&checkpoint)?;
        }

        Ok(WorkflowSummary {
            workflow_id: self.workflow_id.clone(),
            receipts: checkpoint.completed,
            executed_now,
        })
    }

    fn persist(&self, checkpoint: &Checkpoint) -> Result<(), WorkflowError> {
        let bytes = serde_json::to_vec_pretty(checkpoint).map_err(unavailable)?;
        let temp_path = self.dir.join(format!("{CHECKPOINT_FILE}.tmp"));
        let _ = std::fs::remove_file(&temp_path);
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp_path).map_err(unavailable)?;
            file.write_all(&bytes).map_err(unavailable)?;
            file.sync_all().map_err(unavailable)?;
            drop(file);
            std::fs::rename(&temp_path, &self.checkpoint_path).map_err(unavailable)?;
            sync_dir(&self.dir);
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
        result
    }
}

/// Deterministic per-step idempotency key. An effectful step can use this to
/// recognize that its effect already happened and skip it on resume.
pub fn step_idempotency_key(workflow_id: &str, index: usize, name: &str) -> Uuid {
    Uuid::new_v5(
        &WORKFLOW_NAMESPACE,
        format!("{workflow_id}\u{0}{index}\u{0}{name}").as_bytes(),
    )
}

#[cfg(unix)]
fn sync_dir(dir: &Path) {
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

fn unavailable(error: impl std::fmt::Display) -> WorkflowError {
    WorkflowError::Unavailable(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tempfile::tempdir;

    /// A deterministic step that counts how many times it actually executed.
    struct CountingStep {
        name: String,
        runs: Arc<AtomicUsize>,
        fail: bool,
    }

    impl CountingStep {
        fn boxed(name: &str, runs: Arc<AtomicUsize>) -> Box<dyn WorkflowStep> {
            Box::new(Self {
                name: name.to_owned(),
                runs,
                fail: false,
            })
        }
        fn failing(name: &str, runs: Arc<AtomicUsize>) -> Box<dyn WorkflowStep> {
            Box::new(Self {
                name: name.to_owned(),
                runs,
                fail: true,
            })
        }
    }

    impl WorkflowStep for CountingStep {
        fn name(&self) -> &str {
            &self.name
        }
        fn run(&self, context: &StepContext<'_>) -> Result<Vec<u8>, String> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err("boom".into());
            }
            Ok(format!("{}:{}", context.workflow_id, self.name).into_bytes())
        }
    }

    fn steps(names: &[&str], runs: &Arc<AtomicUsize>) -> Vec<Box<dyn WorkflowStep>> {
        names
            .iter()
            .map(|name| CountingStep::boxed(name, runs.clone()))
            .collect()
    }

    #[test]
    fn fresh_run_executes_every_step_once() {
        let dir = tempdir().unwrap();
        let runs = Arc::new(AtomicUsize::new(0));
        let runner = WorkflowRunner::open(dir.path(), "onboard-acme").unwrap();
        let summary = runner
            .run(&steps(&["offer", "invoice", "workspace", "plan"], &runs))
            .unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 4);
        assert_eq!(summary.executed_now, vec![0, 1, 2, 3]);
        assert_eq!(summary.receipts.len(), 4);
    }

    #[test]
    fn resume_after_crash_skips_completed_steps() {
        let dir = tempdir().unwrap();

        // First "process" runs, but crashes after 2 steps: emulate by running
        // a 2-step workflow definition, then extending it on resume.
        let first_runs = Arc::new(AtomicUsize::new(0));
        WorkflowRunner::open(dir.path(), "onboard-acme")
            .unwrap()
            .run(&steps(&["offer", "invoice"], &first_runs))
            .unwrap();
        assert_eq!(first_runs.load(Ordering::SeqCst), 2);

        // But the workflow really has 4 steps. A crash left a checkpoint at 2.
        // Reset done=false to model an interrupted longer workflow.
        let mut checkpoint = WorkflowRunner::open(dir.path(), "onboard-acme")
            .unwrap()
            .checkpoint()
            .unwrap();
        checkpoint.done = false;
        let runner = WorkflowRunner::open(dir.path(), "onboard-acme").unwrap();
        runner.persist(&checkpoint).unwrap();

        // Second "process" (another node) resumes the full 4-step workflow.
        let second_runs = Arc::new(AtomicUsize::new(0));
        let summary = WorkflowRunner::open(dir.path(), "onboard-acme")
            .unwrap()
            .run(&steps(
                &["offer", "invoice", "workspace", "plan"],
                &second_runs,
            ))
            .unwrap();
        // Only the two remaining steps ran; the first two were replayed.
        assert_eq!(second_runs.load(Ordering::SeqCst), 2);
        assert_eq!(summary.executed_now, vec![2, 3]);
        assert_eq!(summary.receipts.len(), 4);
    }

    #[test]
    fn rerunning_a_completed_workflow_executes_nothing() {
        let dir = tempdir().unwrap();
        let runs = Arc::new(AtomicUsize::new(0));
        let names = ["offer", "invoice"];
        WorkflowRunner::open(dir.path(), "wf")
            .unwrap()
            .run(&steps(&names, &runs))
            .unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 2);

        // Idempotent resume: nothing runs again.
        let summary = WorkflowRunner::open(dir.path(), "wf")
            .unwrap()
            .run(&steps(&names, &runs))
            .unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        assert!(summary.executed_now.is_empty());
    }

    #[test]
    fn idempotency_keys_are_deterministic_and_recorded() {
        let dir = tempdir().unwrap();
        let runs = Arc::new(AtomicUsize::new(0));
        let summary = WorkflowRunner::open(dir.path(), "wf")
            .unwrap()
            .run(&steps(&["a", "b"], &runs))
            .unwrap();
        assert_eq!(
            summary.receipts[0].idempotency_key,
            step_idempotency_key("wf", 0, "a")
        );
        assert_ne!(
            summary.receipts[0].idempotency_key,
            summary.receipts[1].idempotency_key
        );
    }

    #[test]
    fn a_failing_step_stops_and_leaves_a_resumable_checkpoint() {
        let dir = tempdir().unwrap();
        let runs = Arc::new(AtomicUsize::new(0));
        let mut with_failure = steps(&["offer"], &runs);
        with_failure.push(CountingStep::failing("invoice", runs.clone()));
        with_failure.push(CountingStep::boxed("plan", runs.clone()));

        let error = WorkflowRunner::open(dir.path(), "wf")
            .unwrap()
            .run(&with_failure)
            .unwrap_err();
        assert!(matches!(error, WorkflowError::StepFailed { .. }));

        // The first step is durably checkpointed; resume runs from step 1.
        let checkpoint = WorkflowRunner::open(dir.path(), "wf")
            .unwrap()
            .checkpoint()
            .unwrap();
        assert_eq!(checkpoint.completed.len(), 1);
        assert!(!checkpoint.done);

        // Now resume with a healthy definition: only steps 1 and 2 run.
        let resume_runs = Arc::new(AtomicUsize::new(0));
        let summary = WorkflowRunner::open(dir.path(), "wf")
            .unwrap()
            .run(&steps(&["offer", "invoice", "plan"], &resume_runs))
            .unwrap();
        assert_eq!(summary.executed_now, vec![1, 2]);
    }

    #[test]
    fn checkpoint_for_a_different_workflow_is_rejected() {
        let dir = tempdir().unwrap();
        let runs = Arc::new(AtomicUsize::new(0));
        WorkflowRunner::open(dir.path(), "wf-a")
            .unwrap()
            .run(&steps(&["x"], &runs))
            .unwrap();
        assert_eq!(
            WorkflowRunner::open(dir.path(), "wf-b")
                .unwrap()
                .checkpoint(),
            Err(WorkflowError::WorkflowMismatch)
        );
    }

    #[test]
    fn resuming_with_fewer_steps_than_completed_fails_closed() {
        let dir = tempdir().unwrap();
        let runs = Arc::new(AtomicUsize::new(0));
        // Complete a four-step workflow.
        WorkflowRunner::open(dir.path(), "wf")
            .unwrap()
            .run(&steps(&["a", "b", "c", "d"], &runs))
            .unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 4);

        // Reopen with a truncated definition — fewer steps than already
        // completed. That can only mean the definition changed under a live
        // checkpoint; the runner must refuse rather than silently drop history.
        let resume_runs = Arc::new(AtomicUsize::new(0));
        let error = WorkflowRunner::open(dir.path(), "wf")
            .unwrap()
            .run(&steps(&["a", "b"], &resume_runs))
            .unwrap_err();
        assert!(matches!(error, WorkflowError::StepDivergence(_)));
        // It failed closed before running anything.
        assert_eq!(resume_runs.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn changed_step_name_under_a_live_checkpoint_fails_closed() {
        let dir = tempdir().unwrap();
        let runs = Arc::new(AtomicUsize::new(0));
        WorkflowRunner::open(dir.path(), "wf")
            .unwrap()
            .run(&steps(&["offer", "invoice"], &runs))
            .unwrap();
        // Reset done to force re-evaluation of the definition.
        let mut checkpoint = WorkflowRunner::open(dir.path(), "wf")
            .unwrap()
            .checkpoint()
            .unwrap();
        checkpoint.done = false;
        let runner = WorkflowRunner::open(dir.path(), "wf").unwrap();
        runner.persist(&checkpoint).unwrap();

        let error = runner
            .run(&steps(&["offer", "RENAMED"], &runs))
            .unwrap_err();
        assert!(matches!(error, WorkflowError::StepDivergence(_)));
    }
}
