//! Stage 1 exit-criterion suite: the whole authorization / replay / audit /
//! backend-downgrade story proven end-to-end through the **assembled product
//! kernel** — the `Store` a founder actually runs — rather than through the
//! individual crates in isolation.
//!
//! The crate-level suites (`crates/*/tests`) prove each boundary on its own,
//! and the live Security Center gauntlet runs the attacks in memory. This
//! module ties them together against the one thing a user executes, and
//! asserts the ROADMAP exit criterion directly:
//!
//!   > A malicious agent cannot read files or execute external actions
//!   > without authorization.

use super::*;
use sovereign_audit_ledger::AuditLedger;
use uuid::Uuid;

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    (dir, store)
}

/// A venture, a customer, and an invoice ready to send. Returns the pending
/// approval id and document id.
fn ready_to_send(store: &Store) -> (Uuid, Uuid) {
    store.set_venture("Acme", "Landing pages").unwrap();
    let workspace = store
        .add_customer("Dr. Tan", "dr.tan@example.com", "")
        .unwrap();
    let customer_id = workspace.customers[0].id;
    let workspace = store
        .create_document(DocumentKind::Invoice, customer_id, Some(250_000), "en")
        .unwrap();
    let document_id = workspace.documents[0].id;
    let workspace = store.request_send(document_id).unwrap();
    (workspace.approvals[0].id, document_id)
}

fn outbox_eml_count(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir.join("outbox"))
        .map(|it| {
            it.flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "eml"))
                .count()
        })
        .unwrap_or(0)
}

fn ledger_actions(dir: &std::path::Path) -> Vec<String> {
    let device = DeviceIdentity::load(&dir.join("device.json")).unwrap();
    AuditLedger::load(&dir.join("ledger.json"), device.public_key_b64())
        .unwrap()
        .events()
        .iter()
        .map(|event| event.action.clone())
        .collect()
}

/// Authorization: nothing an unattended agent can do — draft a document, ask
/// the assistant, request a send — produces a host effect. Only the owner's
/// signed decision does. The `.eml` does not exist until approval.
#[test]
fn no_host_effect_exists_until_the_owner_approves() {
    let (dir, store) = store();
    let (approval_id, document_id) = ready_to_send(&store);

    // The assistant (the "AI") can run, but writes no authoritative state and
    // no effect — only a disclosure.
    let workspace = store.load().unwrap();
    let customer_id = workspace.customers[0].id;
    store.draft_assistant(customer_id, "en").unwrap();

    // Up to and including the pending request, there is no outbox file, no
    // signed approval evidence, and no capability was ever executed.
    assert_eq!(outbox_eml_count(dir.path()), 0);
    let workspace = store.load().unwrap();
    assert_eq!(
        workspace.documents[0].status,
        DocumentStatus::PendingApproval
    );
    assert!(workspace.approvals[0].evidence.is_none());
    let actions = ledger_actions(dir.path());
    assert!(!actions.iter().any(|a| a == "capability.executed"));
    assert!(!actions.iter().any(|a| a == "effect.file_written"));

    // Only the owner's approval unlocks the effect.
    let workspace = store.decide(approval_id, true).unwrap();
    assert_eq!(
        workspace.documents[0].status,
        DocumentStatus::ApprovedPendingDelivery
    );
    assert!(workspace.approvals[0].evidence.is_some());
    assert_eq!(outbox_eml_count(dir.path()), 1);
    let _ = document_id;
}

/// Authorization: a rejected send performs no effect at all.
#[test]
fn a_rejected_send_performs_no_effect() {
    let (dir, store) = store();
    let (approval_id, _document_id) = ready_to_send(&store);

    let workspace = store.decide(approval_id, false).unwrap();
    assert_eq!(workspace.documents[0].status, DocumentStatus::Rejected);
    assert_eq!(outbox_eml_count(dir.path()), 0);
    let actions = ledger_actions(dir.path());
    assert!(actions.iter().any(|a| a == "approval.rejected"));
    assert!(!actions.iter().any(|a| a == "capability.executed"));
}

/// Replay: a decided approval cannot be decided again. The second attempt
/// fails closed and leaves the state and the signed chain untouched — no
/// second capability is consumed and no second `.eml` is written.
#[test]
fn a_decided_approval_cannot_be_replayed() {
    let (dir, store) = store();
    let (approval_id, _document_id) = ready_to_send(&store);
    store.decide(approval_id, true).unwrap();

    let events_after_first = ledger_actions(dir.path()).len();
    let eml_after_first = outbox_eml_count(dir.path());

    assert!(matches!(
        store.decide(approval_id, true),
        Err(WorkspaceError::Invalid(_))
    ));
    assert!(matches!(
        store.decide(approval_id, false),
        Err(WorkspaceError::Invalid(_))
    ));

    assert_eq!(ledger_actions(dir.path()).len(), events_after_first);
    assert_eq!(outbox_eml_count(dir.path()), eml_after_first);
}

/// Audit: every authorized effect leaves signed, ordered evidence, and any
/// later divergence between state and the chain is detected.
#[test]
fn every_authorized_effect_is_signed_ordered_and_tamper_evident() {
    let (dir, store) = store();
    let (approval_id, _document_id) = ready_to_send(&store);
    store.decide(approval_id, true).unwrap();

    // The decision's three events land in order on the verified chain.
    let actions = ledger_actions(dir.path());
    let granted = actions
        .iter()
        .position(|a| a == "approval.granted")
        .unwrap();
    let executed = actions
        .iter()
        .position(|a| a == "capability.executed")
        .unwrap();
    let written = actions
        .iter()
        .position(|a| a == "effect.file_written")
        .unwrap();
    assert!(granted < executed && executed < written);

    // The assembled kernel reconciles clean against its own chain.
    let report = store.integrity_check().unwrap();
    assert!(report.ok && report.findings.is_empty());

    // Hand-editing the vault to fabricate a delivered document (no signed
    // delivery.confirmed) is caught as a critical divergence.
    let mut tampered = store.load().unwrap();
    let workspace = store
        .create_document(DocumentKind::Offer, tampered.customers[0].id, None, "en")
        .unwrap();
    tampered = store.load().unwrap();
    let fresh = workspace.documents.last().unwrap().id;
    tampered
        .documents
        .iter_mut()
        .find(|d| d.id == fresh)
        .unwrap()
        .status = DocumentStatus::Delivered;
    store.save(&tampered).unwrap();
    let report = store.integrity_check().unwrap();
    assert!(!report.ok);
    assert!(report.findings.iter().any(|f| f.severity == "critical"));
}

/// Backend downgrade: the effect ran on the verified pure-compute path, never
/// a V1 or simulated fallback. The evidence carries the exact-binding digests
/// only the V2 executor produces, and the crash-safe execution journal holds
/// exactly one completed record for the run.
#[test]
fn the_authorized_effect_ran_only_on_the_verified_v2_path() {
    let (dir, store) = store();
    let (approval_id, _document_id) = ready_to_send(&store);
    let workspace = store.decide(approval_id, true).unwrap();

    let evidence = workspace.approvals[0].evidence.as_ref().unwrap();
    // V2-only exact-binding evidence: a component digest, a canonical input
    // digest, and a consumed capability idempotency key.
    assert_eq!(evidence.component_digest.len(), 64);
    assert_eq!(evidence.canonical_input_digest.len(), 64);
    assert_eq!(evidence.guest_exit_code, 0);

    // The verified Wasmtime run left exactly one completed journal record.
    let recovered = sovereign_execution::ExecutionJournal::open(dir.path().join("executions"))
        .unwrap()
        .recover()
        .unwrap();
    assert_eq!(recovered.len(), 1);
    assert!(matches!(
        recovered[0].state,
        sovereign_execution::ExecutionState::Completed { .. }
    ));
}
