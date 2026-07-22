//! The approved send as a durable, crash-resumable workflow.
//!
//! Approving a send does real work — compose, the full RFC 0003 kernel chain
//! with its outbox effect, then the audit-first state commit. Routing it
//! through the checkpointed [`WorkflowRunner`] means a crash at any point
//! resumes instead of losing or double-running the effect:
//!
//! - crash **during execute** → no checkpoint, no state: the retry re-runs
//!   the whole step; an orphaned `.eml` from the interrupted attempt is
//!   removed first (no committed state references it, and the recomposed
//!   content is deterministic over the same state);
//! - crash **between execute and commit** → the execute receipt is durable
//!   and the signed record is persisted beside it: the retry replays the
//!   receipt without re-consuming a capability or rewriting the outbox, and
//!   runs only the commit;
//! - crash **inside commit** → the audit-first commit itself guarantees the
//!   chain is never behind the state, and re-running the commit is an
//!   idempotent no-op once the approval is decided.
//!
//! The workflow directory (checkpoint + signed record) is kept after
//! completion as an execution trace; the authoritative copies of the same
//! facts live in the vault and on the signed chain.

use super::store::AuditEntry;
use super::util::{kernel, now};
use super::*;

use sovereign_workflow::{StepContext, WorkflowRunner, WorkflowStep};
use uuid::Uuid;

impl Store {
    /// Run (or resume) the durable send workflow for one pending approval.
    /// The caller has already verified the approval is pending.
    pub(super) fn run_durable_send(
        &self,
        approval_id: Uuid,
        document_id: Uuid,
    ) -> Result<(), WorkspaceError> {
        let workflow_id = format!("send-{approval_id}");
        let dir = self.root.join("workflows").join(&workflow_id);
        let record_path = dir.join("record.json");
        let runner = WorkflowRunner::open(&dir, &workflow_id).map_err(kernel)?;
        let steps: Vec<Box<dyn WorkflowStep>> = vec![
            Box::new(ExecuteSendStep {
                root: self.root.clone(),
                record_path: record_path.clone(),
                approval_id,
                document_id,
            }),
            Box::new(CommitDecisionStep {
                root: self.root.clone(),
                record_path,
                approval_id,
                document_id,
            }),
        ];
        runner.run(&steps).map_err(kernel)?;
        Ok(())
    }

    /// Apply an executed approval to state, audit-first. Idempotent: once the
    /// approval is decided this is a no-op, so a resumed commit step (crash
    /// after the state landed but before the checkpoint) cannot double-apply
    /// or double-record.
    pub(super) fn commit_approve_decision(
        &self,
        approval_id: Uuid,
        document_id: Uuid,
        record: SignedApprovalRecord,
    ) -> Result<(), WorkspaceError> {
        let mut workspace = self.load()?;
        if workspace.approval(approval_id)?.status != ApprovalStatus::Pending {
            return Ok(());
        }

        let approval = workspace.approval_mut(approval_id)?;
        approval.status = ApprovalStatus::Approved;
        approval.decided_at = Some(now());
        approval.evidence = Some(record.clone());
        workspace.document_mut(document_id)?.status = DocumentStatus::ApprovedPendingDelivery;

        let resource = format!("document:{document_id}");
        let mut events = vec![
            AuditEntry {
                action: "approval.granted".into(),
                resource: resource.clone(),
                payload: serde_json::json!({
                    "approval_id": approval_id,
                    "signed_approval_id": record.approval_id,
                    "evidence_digest": record.evidence_digest,
                    "approver_key_id": record.approver_key_id,
                }),
            },
            AuditEntry {
                action: "capability.executed".into(),
                resource: resource.clone(),
                payload: serde_json::json!({
                    "tool": "workspace.delivery/prepare",
                    "component_digest": record.component_digest,
                    "canonical_input_digest": record.canonical_input_digest,
                    "idempotency": record.capability_idempotency,
                    "exit_code": record.guest_exit_code,
                    "fuel": record.fuel_consumed,
                }),
            },
        ];
        if let Some(outbox) = &record.outbox {
            events.push(AuditEntry {
                action: "effect.file_written".into(),
                resource,
                payload: serde_json::json!({
                    "outbox_path": outbox.relative_path,
                    "content_sha256": outbox.content_sha256,
                    "bytes": outbox.bytes,
                }),
            });
        }
        self.commit(&workspace, events)
    }
}

/// Step 1 — compose the message and run the signed kernel chain (the outbox
/// `.eml` is written inside it). The signed record is persisted beside the
/// checkpoint so the commit step can read it on a resumed run: receipts
/// store only output digests, never outputs.
pub(super) struct ExecuteSendStep {
    pub root: std::path::PathBuf,
    pub record_path: std::path::PathBuf,
    pub approval_id: Uuid,
    pub document_id: Uuid,
}

impl WorkflowStep for ExecuteSendStep {
    fn name(&self) -> &str {
        "execute_signed_send"
    }

    fn run(&self, _context: &StepContext<'_>) -> Result<Vec<u8>, String> {
        let store = Store::open(&self.root).map_err(|e| e.to_string())?;
        let workspace = store.load().map_err(|e| e.to_string())?;
        if workspace
            .approval(self.approval_id)
            .map_err(|e| e.to_string())?
            .status
            != ApprovalStatus::Pending
        {
            return Err("approval is no longer pending".into());
        }
        let document = workspace
            .document(self.document_id)
            .map_err(|e| e.to_string())?
            .clone();
        let customer = workspace
            .customers
            .iter()
            .find(|customer| customer.id == document.customer_id);
        let message = compose::compose_email(workspace.venture.as_ref(), customer, &document);

        // An interrupted earlier attempt may have left an orphaned `.eml`
        // (state uncommitted, so nothing references it). Remove it so the
        // exclusive outbox write can run again; the recomposed content is
        // deterministic over the same state.
        let broker =
            sovereign_effects::OutboxBroker::open(self.root.join("outbox")).map_err(kernel_str)?;
        match broker.revoke(&format!("{}.eml", document.id.simple())) {
            Ok(()) | Err(sovereign_effects::EffectError::NotFound) => {}
            Err(error) => return Err(error.to_string()),
        }

        let record = store
            .execute_signed_approval(&document, message.as_bytes())
            .map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
        write_atomic(&self.record_path, &bytes).map_err(|e| e.to_string())?;
        Ok(bytes)
    }
}

/// Step 2 — apply the executed approval to state with the audit-first
/// commit. Reads the signed record persisted by step 1, so it works the same
/// on a fresh run and on a crash resume.
pub(super) struct CommitDecisionStep {
    pub root: std::path::PathBuf,
    pub record_path: std::path::PathBuf,
    pub approval_id: Uuid,
    pub document_id: Uuid,
}

impl WorkflowStep for CommitDecisionStep {
    fn name(&self) -> &str {
        "commit_decision"
    }

    fn run(&self, _context: &StepContext<'_>) -> Result<Vec<u8>, String> {
        let store = Store::open(&self.root).map_err(|e| e.to_string())?;
        let bytes = std::fs::read(&self.record_path)
            .map_err(|_| "missing signed record for an executed send".to_string())?;
        let record: SignedApprovalRecord =
            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        store
            .commit_approve_decision(self.approval_id, self.document_id, record)
            .map_err(|e| e.to_string())?;
        Ok(b"committed".to_vec())
    }
}

fn kernel_str(error: impl std::fmt::Display) -> String {
    kernel(error).to_string()
}

/// Crash-safe replacement write for the persisted record: temp + fsync +
/// rename, mirroring the vault and ledger write pattern.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let temp_path = path.with_extension("tmp");
    let result = (|| {
        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp_path, path)?;
        #[cfg(unix)]
        if let Some(directory) = path.parent() {
            std::fs::File::open(directory)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}
