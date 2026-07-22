use super::compose::compose_email;
use super::*;
use sovereign_audit_ledger::AuditLedger;
use tempfile::tempdir;
use uuid::Uuid;

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    (dir, store)
}

#[test]
fn full_founder_flow_with_approval_and_evidence() {
    let (dir, store) = store();
    store
        .set_venture("Acme Consulting", "Landing pages for clinics")
        .unwrap();
    let workspace = store
        .add_customer("Dr. Tan", "dr.tan@example.com", "met at expo")
        .unwrap();
    let customer_id = workspace.customers[0].id;

    let workspace = store
        .create_document(DocumentKind::Invoice, customer_id, Some(250_000), "en")
        .unwrap();
    let document_id = workspace.documents[0].id;
    assert_eq!(workspace.documents[0].status, DocumentStatus::Draft);

    let workspace = store.request_send(document_id).unwrap();
    assert_eq!(
        workspace.documents[0].status,
        DocumentStatus::PendingApproval
    );
    let approval_id = workspace.approvals[0].id;

    let workspace = store.decide(approval_id, true).unwrap();
    assert_eq!(
        workspace.documents[0].status,
        DocumentStatus::ApprovedPendingDelivery
    );

    // The approval carries real RFC 0003 evidence: signed bytes, the
    // approver's key id, and the sandboxed execution outcome.
    let evidence = workspace.approvals[0].evidence.as_ref().unwrap();
    assert_eq!(evidence.approver_subject_id, "founder-owner");
    assert_eq!(evidence.guest_exit_code, 0);
    assert_eq!(evidence.evidence_digest.len(), 64);
    assert!(!evidence.signed_approval_hex.is_empty());

    // Every step left signed evidence and the chain verifies.
    let device = DeviceIdentity::load(&dir.path().join("device.json")).unwrap();
    let ledger =
        AuditLedger::load(&dir.path().join("ledger.json"), device.public_key_b64()).unwrap();
    let actions: Vec<_> = ledger.events().iter().map(|e| e.action.as_str()).collect();
    assert_eq!(
        actions,
        [
            "venture.update",
            "customer.create",
            "document.draft",
            "approval.requested",
            "approval.granted",
            "capability.executed",
            "effect.file_written",
        ]
    );
    ledger.verify_chain().unwrap();

    // The approval's sandboxed step left crash-safe execution evidence:
    // one completed record in the durable journal.
    let recovered = sovereign_execution::ExecutionJournal::open(dir.path().join("executions"))
        .unwrap()
        .recover()
        .unwrap();
    assert_eq!(recovered.len(), 1);
    assert!(matches!(
        recovered[0].state,
        sovereign_execution::ExecutionState::Completed { .. }
    ));

    // The real host effect happened: the approved document is a genuine
    // file in the local outbox, matching the receipt. It is a composed
    // RFC 5322 message (.eml): real headers, the recipient's address, the
    // document body, and an explicit "not transmitted" marker.
    let outbox_receipt = evidence.outbox.as_ref().unwrap();
    assert!(outbox_receipt.relative_path.ends_with(".eml"));
    let written = std::fs::read(
        dir.path()
            .join("outbox")
            .join(&outbox_receipt.relative_path),
    )
    .unwrap();
    let message = String::from_utf8(written.clone()).unwrap();
    assert!(message.contains("To: \"Dr. Tan\" <dr.tan@example.com>"));
    assert!(message.contains("Subject: "));
    assert!(message.contains("X-Sovereign-Composed:"));
    // The body is present (line endings are normalized to CRLF in the .eml,
    // so match on a body line rather than the raw string).
    let body_line = workspace.documents[0].body.lines().next().unwrap();
    assert!(message.contains(body_line));
    // A real recipient means no placeholder note.
    assert!(!message.contains("placeholder"));
    assert_eq!(outbox_receipt.bytes, written.len());
}

#[test]
fn revoke_delivery_deletes_outbox_and_audits() {
    let (dir, store) = store();
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
    let workspace = store.decide(workspace.approvals[0].id, true).unwrap();
    let outbox_path = workspace.approvals[0]
        .evidence
        .as_ref()
        .unwrap()
        .outbox
        .as_ref()
        .unwrap()
        .relative_path
        .clone();
    let file = dir.path().join("outbox").join(&outbox_path);
    assert!(file.exists());

    let workspace = store.revoke_delivery(document_id).unwrap();
    assert_eq!(workspace.documents[0].status, DocumentStatus::Revoked);
    assert!(!file.exists(), "revoke deletes the composed .eml");

    // The revocation is audited on the same signed chain, and the prior
    // approval evidence is kept — revoking the file does not rewrite the
    // fact that the owner approved.
    let device = DeviceIdentity::load(&dir.path().join("device.json")).unwrap();
    let ledger =
        AuditLedger::load(&dir.path().join("ledger.json"), device.public_key_b64()).unwrap();
    assert_eq!(ledger.events().last().unwrap().action, "effect.revoked");
    ledger.verify_chain().unwrap();
    assert!(workspace.approvals[0].evidence.is_some());

    // A second revoke fails closed (no longer awaiting delivery), and an
    // unknown document is refused.
    assert!(matches!(
        store.revoke_delivery(document_id),
        Err(WorkspaceError::Invalid(_))
    ));
    assert!(matches!(
        store.revoke_delivery(Uuid::new_v4()),
        Err(WorkspaceError::NotFound(_))
    ));
}

#[test]
fn confirm_delivery_is_an_audited_attestation() {
    let (dir, store) = store();
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
    store.decide(workspace.approvals[0].id, true).unwrap();

    let workspace = store.confirm_delivery(document_id).unwrap();
    assert_eq!(workspace.documents[0].status, DocumentStatus::Delivered);

    // The attestation is on the signed chain and honestly marks that the
    // system did not send anything.
    let device = DeviceIdentity::load(&dir.path().join("device.json")).unwrap();
    let ledger =
        AuditLedger::load(&dir.path().join("ledger.json"), device.public_key_b64()).unwrap();
    let last = ledger.events().last().unwrap();
    assert_eq!(last.action, "delivery.confirmed");
    ledger.verify_chain().unwrap();

    // A delivered document cannot be confirmed again or revoked, and an
    // unknown document fails closed.
    assert!(matches!(
        store.confirm_delivery(document_id),
        Err(WorkspaceError::Invalid(_))
    ));
    assert!(matches!(
        store.revoke_delivery(document_id),
        Err(WorkspaceError::Invalid(_))
    ));
    assert!(matches!(
        store.confirm_delivery(Uuid::new_v4()),
        Err(WorkspaceError::NotFound(_))
    ));
}

#[test]
fn integrity_check_binds_state_to_the_signed_chain() {
    let (dir, store) = store();
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
    store.decide(workspace.approvals[0].id, true).unwrap();

    // A workspace built only through the audited API reconciles cleanly.
    let clean = store.integrity_check().unwrap();
    assert!(clean.ok && clean.chain_verified);
    assert!(clean.findings.is_empty());
    assert!(clean.events > 0);

    // Fabricate state the way a hand-edited vault would: flip the delivered
    // status onto a document that never went through the audited path. The
    // signed chain has no delivery.confirmed for it, so the check catches it.
    let mut tampered = store.load().unwrap();
    tampered.documents[0].status = DocumentStatus::Delivered;
    store.save(&tampered).unwrap();

    let report = store.integrity_check().unwrap();
    assert!(!report.ok);
    assert!(report.chain_verified, "the chain itself is still intact");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.detail.contains("delivery.confirmed")
                && finding.resource == format!("document:{document_id}")),
        "expected a finding for the fabricated delivered state, got {:?}",
        report.findings
    );

    // Corrupting the signed chain itself fails closed before any cross-check.
    let ledger_path = dir.path().join("ledger.json");
    let mut events: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ledger_path).unwrap()).unwrap();
    events[0]["resource"] = serde_json::json!("document:forged");
    std::fs::write(&ledger_path, serde_json::to_vec(&events).unwrap()).unwrap();

    let broken = store.integrity_check().unwrap();
    assert!(!broken.chain_verified && !broken.ok);
    assert_eq!(broken.findings[0].resource, "ledger.json");
}

#[test]
fn draft_assistant_records_a_persistent_data_disclosure() {
    let (dir, store) = store();
    store.set_venture("Acme", "Landing pages").unwrap();
    let workspace = store
        .add_customer("Dr. Tan", "dr.tan@example.com", "")
        .unwrap();
    let customer_id = workspace.customers[0].id;

    // The suggestion is powerless, but the disclosure is durable.
    let suggestion = store.draft_assistant(customer_id, "en").unwrap();
    assert!(
        !suggestion.saved,
        "a suggestion is never authoritative state"
    );

    let workspace = store.load().unwrap();
    assert_eq!(workspace.disclosures.len(), 1);
    let disclosure = &workspace.disclosures[0];
    assert_eq!(disclosure.customer_id, customer_id);
    assert_eq!(disclosure.data_class, "amber");
    assert!(
        disclosure.stayed_local && disclosure.provider_trust == "local",
        "Amber customer data must stay on this machine"
    );
    assert!(disclosure.output_chars > 0);

    // The persisted log mirrors a signed model.drafted event on the chain —
    // detail in state, tamper-evidence on the ledger.
    let device = DeviceIdentity::load(&dir.path().join("device.json")).unwrap();
    let ledger =
        AuditLedger::load(&dir.path().join("ledger.json"), device.public_key_b64()).unwrap();
    ledger.verify_chain().unwrap();
    assert!(ledger
        .events()
        .iter()
        .any(|event| event.action == "model.drafted"
            && event.resource == format!("customer:{customer_id}")));

    // A second call appends rather than replaces: the log is a history.
    store.draft_assistant(customer_id, "zh").unwrap();
    assert_eq!(store.load().unwrap().disclosures.len(), 2);
}

#[test]
fn interrupted_operation_is_a_warning_and_retry_heals_it() {
    let (_dir, store) = store();
    store.set_venture("Acme", "Landing pages").unwrap();
    store.add_customer("Dr. Tan", "", "").unwrap();

    // Simulate a crash in the commit window: commits are audit-first, so the
    // chain already carries customer.create while the state write never
    // landed. Rewind the state to just before the customer.
    let mut behind = store.load().unwrap();
    behind.customers.clear();
    store.save(&behind).unwrap();

    let report = store.integrity_check().unwrap();
    assert!(
        report.ok,
        "an interrupted operation must not read as tampering"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.severity == "warning" && finding.detail.contains("interrupted")),
        "expected an interrupted-operation warning, got {:?}",
        report.findings
    );

    // Retrying the operation heals the audit: the new tail matches state.
    store.add_customer("Dr. Tan", "", "").unwrap();
    let healed = store.integrity_check().unwrap();
    assert!(
        healed.ok && healed.findings.is_empty(),
        "{:?}",
        healed.findings
    );
}

#[test]
fn torn_decision_is_a_warning_until_state_lands() {
    let (_dir, store) = store();
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
    let approval_id = workspace.approvals[0].id;
    store.decide(approval_id, true).unwrap();

    // Tear the decision: the chain holds approval.granted /
    // capability.executed / effect.file_written, but roll the state back to
    // pending as if the vault write never completed.
    let mut behind = store.load().unwrap();
    behind.approvals[0].status = ApprovalStatus::Pending;
    behind.approvals[0].evidence = None;
    behind.documents[0].status = DocumentStatus::PendingApproval;
    store.save(&behind).unwrap();

    let report = store.integrity_check().unwrap();
    assert!(report.ok, "a torn decision is interrupted, not tampering");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.severity == "warning"),
        "expected a warning for the torn decision, got {:?}",
        report.findings
    );
}

#[test]
fn durable_send_resumes_after_crash_without_rerunning_the_effect() {
    use super::send_workflow::ExecuteSendStep;
    use sovereign_workflow::{WorkflowRunner, WorkflowStep};

    let (dir, store) = store();
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
    let approval_id = workspace.approvals[0].id;

    // Simulate a crash between execute and commit: run only the first step
    // of the same workflow the app would run, then "die".
    let workflow_id = format!("send-{approval_id}");
    let wf_dir = dir.path().join("workflows").join(&workflow_id);
    let record_path = wf_dir.join("record.json");
    let runner = WorkflowRunner::open(&wf_dir, &workflow_id).unwrap();
    let only_execute: Vec<Box<dyn WorkflowStep>> = vec![Box::new(ExecuteSendStep {
        root: dir.path().to_path_buf(),
        record_path: record_path.clone(),
        approval_id,
        document_id,
    })];
    runner.run(&only_execute).unwrap();

    // Effect happened, record persisted — but state still pending.
    assert!(record_path.exists());
    assert_eq!(
        store.load().unwrap().approvals[0].status,
        ApprovalStatus::Pending
    );
    let persisted: SignedApprovalRecord =
        serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();

    // The retry (the owner clicks approve again) resumes: the execute
    // receipt replays, only the commit runs — no second capability, no
    // second outbox write.
    let workspace = store.decide(approval_id, true).unwrap();
    assert_eq!(workspace.approvals[0].status, ApprovalStatus::Approved);
    assert_eq!(
        workspace.documents[0].status,
        DocumentStatus::ApprovedPendingDelivery
    );
    let evidence = workspace.approvals[0].evidence.as_ref().unwrap();
    assert_eq!(
        evidence.capability_idempotency, persisted.capability_idempotency,
        "the committed evidence must be the persisted record, not a re-execution"
    );
    let eml_count = std::fs::read_dir(dir.path().join("outbox"))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|x| x == "eml"))
        .count();
    assert_eq!(eml_count, 1, "exactly one composed message, no duplicates");

    let report = store.integrity_check().unwrap();
    assert!(
        report.ok && report.findings.is_empty(),
        "{:?}",
        report.findings
    );
}

#[test]
fn durable_send_retries_after_crash_mid_execute() {
    let (dir, store) = store();
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
    let approval_id = workspace.approvals[0].id;

    // Simulate a crash mid-execute: the outbox file landed but neither the
    // workflow checkpoint nor any state did — an orphan nothing references.
    let broker = sovereign_effects::OutboxBroker::open(dir.path().join("outbox")).unwrap();
    broker
        .write_message(
            &document_id.simple().to_string(),
            sovereign_effects::EffectDataClass::Amber,
            b"orphan from an interrupted attempt",
        )
        .unwrap();

    // The retry pre-cleans the orphan and completes end-to-end.
    let workspace = store.decide(approval_id, true).unwrap();
    assert_eq!(workspace.approvals[0].status, ApprovalStatus::Approved);
    let outbox = workspace.approvals[0]
        .evidence
        .as_ref()
        .unwrap()
        .outbox
        .as_ref()
        .unwrap();
    let content = std::fs::read(dir.path().join("outbox").join(&outbox.relative_path)).unwrap();
    assert!(
        content.starts_with(b"From:"),
        "the orphan was replaced by the real composed message"
    );
}

#[test]
fn commit_approve_decision_is_idempotent() {
    let (dir, store) = store();
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
    let approval_id = workspace.approvals[0].id;
    let workspace = store.decide(approval_id, true).unwrap();
    let record = workspace.approvals[0].evidence.clone().unwrap();

    let device = DeviceIdentity::load(&dir.path().join("device.json")).unwrap();
    let before =
        AuditLedger::load(&dir.path().join("ledger.json"), device.public_key_b64()).unwrap();
    let events_before = before.events().len();

    // A resumed commit step after the state already landed must change
    // nothing and append nothing.
    store
        .commit_approve_decision(approval_id, document_id, record)
        .unwrap();
    let after =
        AuditLedger::load(&dir.path().join("ledger.json"), device.public_key_b64()).unwrap();
    assert_eq!(after.events().len(), events_before);
    assert_eq!(
        store.load().unwrap().approvals[0].status,
        ApprovalStatus::Approved
    );
}

#[test]
fn compose_email_is_wellformed_and_injection_safe() {
    let venture = Venture {
        name: "Acme".into(),
        service: "Landing pages".into(),
        updated_at: 0,
    };
    let document = Document {
        id: Uuid::new_v4(),
        kind: DocumentKind::Offer,
        customer_id: Uuid::new_v4(),
        title: "Offer — Acme".into(),
        body: "Hello,\nHere is the offer.\n".into(),
        amount_cents: None,
        status: DocumentStatus::PendingApproval,
        created_at: 0,
    };

    // With a real address the To header resolves and there is no placeholder.
    let with_email = Customer {
        id: document.customer_id,
        name: "Dr. Tan".into(),
        email: "dr.tan@example.com".into(),
        notes: String::new(),
        created_at: 0,
    };
    let message = compose_email(Some(&venture), Some(&with_email), &document);
    assert!(message.contains("From: Acme <founder@example.invalid>"));
    assert!(message.contains("To: \"Dr. Tan\" <dr.tan@example.com>"));
    assert!(message.contains("Subject: Offer — Acme"));
    assert!(message.contains("Message-ID: <"));
    assert!(message.contains("X-Sovereign-Composed:"));
    assert!(!message.contains("placeholder"));
    assert!(message.contains("Here is the offer."));
    // Headers are CRLF-separated and end before the body.
    assert!(message.contains("\r\n\r\n"));

    // With no address the recipient is an RFC 2606 placeholder, flagged.
    let no_email = Customer {
        email: String::new(),
        ..with_email.clone()
    };
    let message = compose_email(Some(&venture), Some(&no_email), &document);
    assert!(message.contains("<recipient@example.invalid>"));
    assert!(message.contains("X-Sovereign-Note: recipient address is a placeholder"));

    // A hostile display name cannot inject headers: it is quoted/stripped,
    // never allowed to introduce a bare CRLF + header.
    let hostile = Customer {
        name: "Bad\r\nBcc: victim@example.com".into(),
        email: "x@example.com".into(),
        ..with_email.clone()
    };
    let message = compose_email(Some(&venture), Some(&hostile), &document);
    let header_block = message.split("\r\n\r\n").next().unwrap();
    assert!(!header_block.to_ascii_lowercase().contains("\r\nbcc:"));
}

#[test]
fn double_decision_and_unknown_ids_fail_closed() {
    let (_dir, store) = store();
    store.set_venture("Acme", "Service").unwrap();
    let workspace = store.add_customer("Customer", "", "").unwrap();
    let customer_id = workspace.customers[0].id;
    let workspace = store
        .create_document(DocumentKind::Offer, customer_id, None, "zh")
        .unwrap();
    let document_id = workspace.documents[0].id;
    let workspace = store.request_send(document_id).unwrap();
    let approval_id = workspace.approvals[0].id;

    store.decide(approval_id, false).unwrap();
    assert!(matches!(
        store.decide(approval_id, true),
        Err(WorkspaceError::Invalid(_))
    ));
    assert!(matches!(
        store.decide(Uuid::new_v4(), true),
        Err(WorkspaceError::NotFound(_))
    ));
    assert!(matches!(
        store.request_send(Uuid::new_v4()),
        Err(WorkspaceError::NotFound(_))
    ));
    // A non-draft document cannot be resubmitted.
    assert!(matches!(
        store.request_send(document_id),
        Err(WorkspaceError::Invalid(_))
    ));
}

#[test]
fn amount_parsing_is_exact_and_bounded() {
    assert_eq!(parse_amount_cents("2500").unwrap(), 250_000);
    assert_eq!(parse_amount_cents("2500.5").unwrap(), 250_050);
    assert_eq!(parse_amount_cents("2500.50").unwrap(), 250_050);
    assert_eq!(parse_amount_cents("0.09").unwrap(), 9);
    for bad in ["", "-5", "1.234", "abc", "1e3", "999999999999999999"] {
        assert!(parse_amount_cents(bad).is_err(), "{bad} should fail");
    }
}

#[test]
fn export_contains_state_and_verified_chain() {
    let (_dir, store) = store();
    store.set_venture("Acme", "Service").unwrap();
    let export = store.export().unwrap();
    assert_eq!(export["format"], "sovereign-founder-os-export");
    assert_eq!(export["audit_chain_verified"], true);
    assert_eq!(export["workspace"]["venture"]["name"], "Acme");
}

#[test]
fn draft_assistant_never_touches_authoritative_business_state() {
    let (_dir, store) = store();
    store.set_venture("Acme", "Landing pages").unwrap();
    let workspace = store.add_customer("Dr. Tan", "", "").unwrap();
    let customer_id = workspace.customers[0].id;
    let before = store.load().unwrap();

    let suggestion = store.draft_assistant(customer_id, "en").unwrap();
    assert!(!suggestion.saved);
    assert_eq!(suggestion.provider_trust, "local");
    assert!(suggestion.text.contains("Dr. Tan"));

    let after = store.load().unwrap();
    // The untrusted suggestion is powerless: the business graph — venture,
    // customers, documents, approvals — is byte-for-byte unchanged, and the
    // suggestion text is never persisted anywhere in state.
    let business = |workspace: &Workspace| {
        serde_json::json!({
            "venture": workspace.venture,
            "customers": workspace.customers,
            "documents": workspace.documents,
            "approvals": workspace.approvals,
        })
    };
    assert_eq!(business(&before), business(&after));
    assert!(after.documents.is_empty());
    let serialized = serde_json::to_string(&after).unwrap();
    assert!(
        !serialized.contains(&suggestion.text),
        "the model suggestion must never be written to authoritative state"
    );

    // The only durable change is an append to the owner-visible disclosure
    // log, mirrored by exactly one signed model.drafted event.
    assert_eq!(after.disclosures.len(), 1);
    let device = DeviceIdentity::load(&_dir.path().join("device.json")).unwrap();
    let ledger =
        AuditLedger::load(&_dir.path().join("ledger.json"), device.public_key_b64()).unwrap();
    assert_eq!(ledger.events().last().unwrap().action, "model.drafted");
}

#[test]
fn command_center_guidance_tracks_state_deterministically() {
    let kinds = |store: &Store| -> Vec<String> {
        store
            .command_center()
            .unwrap()
            .guidance
            .into_iter()
            .map(|item| item.kind)
            .collect()
    };

    let (_dir, store) = store();
    // Empty: the only meaningful step is naming the venture.
    assert_eq!(kinds(&store), vec!["set_venture"]);

    // Venture but no customers.
    store.set_venture("Acme", "Landing pages").unwrap();
    assert_eq!(kinds(&store), vec!["add_customer"]);

    // A customer with no documents → draft_for that customer.
    let workspace = store.add_customer("Dr. Tan", "", "").unwrap();
    let customer_id = workspace.customers[0].id;
    assert_eq!(kinds(&store), vec!["draft_for"]);

    // A document exists but the customer has no email → add_email risk
    // surfaces, and there is now a draft to send.
    store
        .create_document(DocumentKind::Invoice, customer_id, Some(250_000), "en")
        .unwrap();
    let guidance = store.command_center().unwrap().guidance;
    let kinds_now: Vec<&str> = guidance.iter().map(|item| item.kind.as_str()).collect();
    assert!(kinds_now.contains(&"send_drafts"));
    assert!(kinds_now.contains(&"add_email"));
    let email_item = guidance
        .iter()
        .find(|item| item.kind == "add_email")
        .unwrap();
    assert_eq!(email_item.kind_class, "risk");
    assert_eq!(email_item.subject, "Dr. Tan");
    let send_item = guidance
        .iter()
        .find(|item| item.kind == "send_drafts")
        .unwrap();
    assert_eq!(send_item.count, 1);

    // Determinism: recomputing yields the identical list.
    assert_eq!(
        serde_json::to_value(&guidance).unwrap(),
        serde_json::to_value(&store.command_center().unwrap().guidance).unwrap()
    );
}

#[test]
fn command_center_guidance_reports_pending_and_all_clear() {
    let (_dir, store) = store();
    store.set_venture("Acme", "Landing pages").unwrap();
    let workspace = store
        .add_customer("Dr. Tan", "dr.tan@example.com", "")
        .unwrap();
    let customer_id = workspace.customers[0].id;
    let workspace = store
        .create_document(DocumentKind::Invoice, customer_id, Some(250_000), "en")
        .unwrap();
    let document_id = workspace.documents[0].id;

    // A pending decision is the top action.
    let workspace = store.request_send(document_id).unwrap();
    let approval_id = workspace.approvals[0].id;
    let guidance = store.command_center().unwrap().guidance;
    assert_eq!(guidance[0].kind, "decide_pending");
    assert_eq!(guidance[0].count, 1);

    // Once decided, with an emailed customer and no drafts left, the founder
    // is caught up.
    store.decide(approval_id, true).unwrap();
    let kinds: Vec<String> = store
        .command_center()
        .unwrap()
        .guidance
        .into_iter()
        .map(|item| item.kind)
        .collect();
    assert_eq!(kinds, vec!["all_clear"]);
}

#[test]
fn verify_export_accepts_genuine_bundle_and_rejects_tampering() {
    let (_dir, store) = store();
    store.set_venture("Acme", "Landing pages").unwrap();
    let workspace = store.add_customer("Dr. Tan", "", "expo").unwrap();
    let customer_id = workspace.customers[0].id;
    let workspace = store
        .create_document(DocumentKind::Invoice, customer_id, Some(250_000), "en")
        .unwrap();
    let document_id = workspace.documents[0].id;
    let workspace = store.request_send(document_id).unwrap();
    store.decide(workspace.approvals[0].id, true).unwrap();

    let bundle = store.export().unwrap();

    // A genuine export verifies end to end: format, identity binding, and
    // the full signed chain.
    let report = verify_export(&bundle).unwrap();
    assert!(
        report.ok,
        "genuine bundle should verify: {:?}",
        report.notes
    );
    assert!(report.format_ok);
    assert!(report.identity_bound);
    assert!(report.audit_chain_verified);
    assert!(report.audit_events >= 1);
    assert_eq!(report.customers, 1);
    assert_eq!(report.documents, 1);
    assert_eq!(report.signed_approvals, 1);

    // Tampering with a recorded action breaks the signed chain and is
    // caught — the verifier fails closed and says why.
    let mut tampered = bundle.clone();
    tampered["audit_events"][0]["action"] = serde_json::Value::String("tampered.action".into());
    let report = verify_export(&tampered).unwrap();
    assert!(!report.ok);
    assert!(!report.audit_chain_verified);
    assert!(report.notes.iter().any(|note| note.contains("chain")));

    // Swapping the declared device_id (identity spoof) is caught even when
    // the chain itself is internally consistent.
    let mut spoofed = bundle.clone();
    spoofed["device_id"] = serde_json::Value::String("dev_000000000000000000000000".into());
    let report = verify_export(&spoofed).unwrap();
    assert!(!report.ok);
    assert!(!report.identity_bound);
    assert!(
        report.audit_chain_verified,
        "chain is untouched by an id swap"
    );

    // A foreign format tag is refused outright.
    let mut wrong_format = bundle.clone();
    wrong_format["format"] = serde_json::Value::String("not-our-export".into());
    assert!(!verify_export(&wrong_format).unwrap().format_ok);
}

#[test]
fn command_center_aggregates_state_and_evidence_read_only() {
    let (_dir, store) = store();
    store.set_venture("Acme", "Landing pages").unwrap();
    let workspace = store.add_customer("Dr. Tan", "", "").unwrap();
    let customer_id = workspace.customers[0].id;
    let workspace = store
        .create_document(DocumentKind::Invoice, customer_id, Some(250_000), "en")
        .unwrap();
    let document_id = workspace.documents[0].id;

    // A pending decision shows up as actionable, with no evidence yet.
    let workspace = store.request_send(document_id).unwrap();
    let approval_id = workspace.approvals[0].id;
    let cc = store.command_center().unwrap();
    assert_eq!(cc.venture.as_ref().unwrap().name, "Acme");
    assert_eq!(cc.counts.customers, 1);
    assert_eq!(cc.counts.pending_approval, 1);
    assert_eq!(cc.pending_decisions.len(), 1);
    assert_eq!(cc.pending_decisions[0].customer_name, "Dr. Tan");
    assert_eq!(cc.evidence.signed_approvals, 0);
    assert_eq!(cc.evidence.outbox_effects, 0);

    // After approval the evidence rollup reflects the real signed effect,
    // and the decision is no longer pending.
    let ledger_before = {
        let device = DeviceIdentity::load(&_dir.path().join("device.json")).unwrap();
        AuditLedger::load(&_dir.path().join("ledger.json"), device.public_key_b64())
            .unwrap()
            .events()
            .len()
    };
    store.decide(approval_id, true).unwrap();
    let cc = store.command_center().unwrap();
    assert!(cc.pending_decisions.is_empty());
    assert_eq!(cc.counts.approved_pending_delivery, 1);
    assert_eq!(cc.evidence.signed_approvals, 1);
    assert_eq!(cc.evidence.outbox_effects, 1);
    assert!(cc.evidence.last_effect_path.is_some());

    // The view is genuinely read-only: computing it twice appends no audit
    // events beyond the ones the approval itself created.
    let _ = store.command_center().unwrap();
    let device = DeviceIdentity::load(&_dir.path().join("device.json")).unwrap();
    let ledger_after = AuditLedger::load(&_dir.path().join("ledger.json"), device.public_key_b64())
        .unwrap()
        .events()
        .len();
    // Approval added exactly its own events (granted, executed, effect);
    // the two command_center calls added none.
    assert_eq!(ledger_after, ledger_before + 3);
}
