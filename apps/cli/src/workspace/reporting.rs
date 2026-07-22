use super::types::document_status_label;
use super::util::{now, storage};
use super::*;

use sovereign_audit_ledger::AuditLedger;

impl Store {
    /// Aggregate the whole workspace into the Founder Command Center view.
    /// Pure over stored state: it reads nothing new and writes nothing, so it
    /// leaves no audit event and makes no security claim of its own.
    pub fn command_center(&self) -> Result<CommandCenter, WorkspaceError> {
        let workspace = self.load()?;

        let count_status = |status: DocumentStatus| {
            workspace
                .documents
                .iter()
                .filter(|document| document.status == status)
                .count()
        };
        let counts = CommandCenterCounts {
            customers: workspace.customers.len(),
            documents: workspace.documents.len(),
            drafts: count_status(DocumentStatus::Draft),
            pending_approval: count_status(DocumentStatus::PendingApproval),
            approved_pending_delivery: count_status(DocumentStatus::ApprovedPendingDelivery),
            rejected: count_status(DocumentStatus::Rejected),
        };

        let pending_decisions: Vec<PendingDecision> = workspace
            .approvals
            .iter()
            .filter(|approval| approval.status == ApprovalStatus::Pending)
            .map(|approval| {
                let document = workspace
                    .documents
                    .iter()
                    .find(|document| document.id == approval.document_id);
                let customer_name = document
                    .and_then(|document| {
                        workspace
                            .customers
                            .iter()
                            .find(|customer| customer.id == document.customer_id)
                    })
                    .map(|customer| customer.name.clone())
                    .unwrap_or_default();
                PendingDecision {
                    approval_id: approval.id,
                    document_id: approval.document_id,
                    document_title: document
                        .map(|document| document.title.clone())
                        .unwrap_or_default(),
                    customer_name,
                    action: approval.action.clone(),
                    policy_reason: approval.policy_reason.clone(),
                    requested_at: approval.requested_at,
                }
            })
            .collect();

        let signed_approvals = workspace
            .approvals
            .iter()
            .filter(|approval| approval.evidence.is_some())
            .count();
        let effects: Vec<&OutboxWrite> = workspace
            .approvals
            .iter()
            .filter_map(|approval| approval.evidence.as_ref())
            .filter_map(|evidence| evidence.outbox.as_ref())
            .collect();
        let evidence = EvidenceRollup {
            signed_approvals,
            outbox_effects: effects.len(),
            last_effect_path: effects.last().map(|effect| effect.relative_path.clone()),
        };

        let guidance = derive_guidance(&workspace, &counts, pending_decisions.len());

        Ok(CommandCenter {
            venture: workspace.venture,
            counts,
            pending_decisions,
            evidence,
            guidance,
        })
    }

    /// Self-audit: reconcile the authoritative workspace state against the
    /// signed audit chain and report every divergence.
    ///
    /// The audit ledger is tamper-evident for itself — `AuditLedger::load`
    /// re-verifies the hash chain and every device signature — but the vault
    /// that holds authoritative state is a *separate* file. Nothing otherwise
    /// stops someone from hand-editing `workspace.json` to fabricate state
    /// (flip a document to approved, invent a customer) without a matching
    /// signed event. This check binds the two: it fails closed if the chain
    /// does not verify, then confirms that every power-granting state has the
    /// signed evidence that should exist for it. It is deliberately modest —
    /// the ledger stores payload *hashes*, not payloads, so this proves that
    /// signed evidence *exists* for a state, not that a field's value matches.
    pub fn integrity_check(&self) -> Result<IntegrityReport, WorkspaceError> {
        let workspace = self.load()?;
        let ledger_path = self.root.join("ledger.json");

        let (events, chain_verified, load_error) = if ledger_path.exists() {
            match AuditLedger::load(&ledger_path, self.device.public_key_b64()) {
                Ok(ledger) => (ledger.events().to_vec(), true, None),
                Err(error) => (Vec::new(), false, Some(error.to_string())),
            }
        } else {
            (Vec::new(), true, None)
        };

        let mut findings = Vec::new();

        // A chain that will not verify is a critical failure on its own, and it
        // makes every downstream cross-check meaningless — so stop here.
        if !chain_verified {
            findings.push(IntegrityFinding {
                severity: "critical",
                resource: "ledger.json".into(),
                detail: format!(
                    "the signed audit chain failed verification: {}",
                    load_error.unwrap_or_else(|| "unknown error".into())
                ),
            });
            return Ok(IntegrityReport {
                chain_verified,
                events: events.len(),
                ok: false,
                findings,
            });
        }

        let has = |action: &str, resource: &str| {
            events
                .iter()
                .any(|event| event.action == action && event.resource == resource)
        };

        // Every customer in state must have a signed creation event.
        for customer in &workspace.customers {
            let resource = format!("customer:{}", customer.id);
            if !has("customer.create", &resource) {
                findings.push(IntegrityFinding {
                    severity: "critical",
                    resource,
                    detail: format!(
                        "customer \"{}\" exists in state with no signed customer.create event",
                        customer.name
                    ),
                });
            }
        }

        // Every state that grants power or records an effect must be backed by
        // the signed event that should have produced it.
        for document in &workspace.documents {
            let resource = format!("document:{}", document.id);
            let approved = matches!(
                document.status,
                DocumentStatus::ApprovedPendingDelivery
                    | DocumentStatus::Revoked
                    | DocumentStatus::Delivered
            );
            if approved && !has("approval.granted", &resource) {
                findings.push(IntegrityFinding {
                    severity: "critical",
                    resource: resource.clone(),
                    detail: format!(
                        "document \"{}\" is {} with no signed approval.granted event",
                        document.title,
                        document_status_label(document.status)
                    ),
                });
            }
            if document.status == DocumentStatus::Revoked && !has("effect.revoked", &resource) {
                findings.push(IntegrityFinding {
                    severity: "critical",
                    resource: resource.clone(),
                    detail: format!(
                        "document \"{}\" is revoked with no signed effect.revoked event",
                        document.title
                    ),
                });
            }
            if document.status == DocumentStatus::Delivered && !has("delivery.confirmed", &resource)
            {
                findings.push(IntegrityFinding {
                    severity: "critical",
                    resource,
                    detail: format!(
                        "document \"{}\" is delivered with no signed delivery.confirmed event",
                        document.title
                    ),
                });
            }
        }

        // Any approval that records an outbox effect must have the signed write.
        for approval in &workspace.approvals {
            let claims_outbox = approval
                .evidence
                .as_ref()
                .is_some_and(|evidence| evidence.outbox.is_some());
            if claims_outbox {
                let resource = format!("document:{}", approval.document_id);
                if !has("effect.file_written", &resource) {
                    findings.push(IntegrityFinding {
                        severity: "critical",
                        resource,
                        detail:
                            "an approval records an outbox effect with no signed effect.file_written event"
                                .into(),
                    });
                }
            }
        }

        Ok(IntegrityReport {
            chain_verified,
            events: events.len(),
            ok: findings.is_empty(),
            findings,
        })
    }

    /// Full data export: the founder's right to leave with everything.
    pub fn export(&self) -> Result<serde_json::Value, WorkspaceError> {
        let workspace = self.load()?;
        let ledger_path = self.root.join("ledger.json");
        let (events, chain_ok) = if ledger_path.exists() {
            match AuditLedger::load(&ledger_path, self.device.public_key_b64()) {
                Ok(ledger) => (
                    serde_json::to_value(ledger.events()).map_err(storage)?,
                    true,
                ),
                Err(_) => (serde_json::Value::Array(Vec::new()), false),
            }
        } else {
            (serde_json::Value::Array(Vec::new()), true)
        };
        self.record("workspace.export", "workspace:all", serde_json::json!({}))?;
        Ok(serde_json::json!({
            "format": EXPORT_FORMAT,
            "version": 1,
            "exported_at_unix": now(),
            "device_id": self.device.device_id(),
            "workspace": workspace,
            "audit_chain_verified": chain_ok,
            "audit_events": events,
        }))
    }
}

/// Derive the Command Center's next-steps and risks from state alone. Ordered
/// most-important first and capped, so the founder sees a short, actionable
/// list. Deterministic: the same workspace always produces the same guidance,
/// and no model is consulted — these are observations, not predictions.
fn derive_guidance(
    workspace: &Workspace,
    counts: &CommandCenterCounts,
    pending: usize,
) -> Vec<Guidance> {
    // Before a venture exists nothing else is meaningful — name it first.
    if workspace.venture.is_none() {
        return vec![Guidance::action("set_venture")];
    }

    let mut out = Vec::new();

    // The founder is the bottleneck for pending decisions: surface them first.
    if pending > 0 {
        out.push(Guidance::action("decide_pending").with_count(pending));
    }
    if workspace.customers.is_empty() {
        out.push(Guidance::action("add_customer"));
    }
    if counts.drafts > 0 {
        out.push(Guidance::action("send_drafts").with_count(counts.drafts));
    }

    // Risk: a customer who already has documents but no email — a send would be
    // addressed to a placeholder the founder must fix before delivering.
    if let Some(customer) = workspace.customers.iter().find(|customer| {
        customer.email.trim().is_empty()
            && workspace
                .documents
                .iter()
                .any(|document| document.customer_id == customer.id)
    }) {
        out.push(Guidance::risk("add_email").with_subject(customer.name.clone()));
    }

    // A customer with no documents yet — an obvious next draft.
    if let Some(customer) = workspace.customers.iter().find(|customer| {
        !workspace
            .documents
            .iter()
            .any(|document| document.customer_id == customer.id)
    }) {
        out.push(Guidance::action("draft_for").with_subject(customer.name.clone()));
    }

    if out.is_empty() {
        out.push(Guidance::action("all_clear"));
    }

    out.truncate(5);
    out
}
