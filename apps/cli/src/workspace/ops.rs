use super::compose::{compose_email, draft_outreach_note, render_document};
use super::util::{clean_email, clean_optional_text, clean_text, kernel, now};
use super::*;

use sovereign_contracts::{AutomationLevel, DataClass};
use sovereign_model::{DeterministicProvider, Health as ModelHealth, ModelGateway, ModelRequest};
use uuid::Uuid;

impl Store {
    pub fn set_venture(&self, name: &str, service: &str) -> Result<Workspace, WorkspaceError> {
        let name = clean_text("name", name)?;
        let service = clean_text("service", service)?;
        let (allowed, _, reason) = self.check_policy(
            "workspace",
            "update",
            "venture:profile",
            DataClass::Amber,
            AutomationLevel::L1Draft,
        );
        if !allowed {
            return Err(WorkspaceError::PolicyDenied(reason));
        }
        let mut workspace = self.load()?;
        workspace.version = WORKSPACE_VERSION;
        workspace.venture = Some(Venture {
            name: name.clone(),
            service,
            updated_at: now(),
        });
        self.save(&workspace)?;
        self.record(
            "venture.update",
            "venture:profile",
            serde_json::json!({ "name": name }),
        )?;
        Ok(workspace)
    }

    pub fn add_customer(
        &self,
        name: &str,
        email: &str,
        notes: &str,
    ) -> Result<Workspace, WorkspaceError> {
        let name = clean_text("name", name)?;
        let email = clean_email(email)?;
        let notes = clean_optional_text("notes", notes)?;
        let (allowed, _, reason) = self.check_policy(
            "workspace",
            "update",
            "customer:new",
            DataClass::Amber,
            AutomationLevel::L1Draft,
        );
        if !allowed {
            return Err(WorkspaceError::PolicyDenied(reason));
        }
        let mut workspace = self.load()?;
        if workspace.customers.len() >= MAX_CUSTOMERS {
            return Err(WorkspaceError::Invalid("customer limit reached".into()));
        }
        let customer = Customer {
            id: Uuid::new_v4(),
            name: name.clone(),
            email,
            notes,
            created_at: now(),
        };
        let resource = format!("customer:{}", customer.id);
        workspace.customers.push(customer);
        self.save(&workspace)?;
        self.record(
            "customer.create",
            &resource,
            serde_json::json!({ "name": name }),
        )?;
        Ok(workspace)
    }

    /// Ask the local drafting assistant for a suggested outreach note. This is
    /// the model layer in action, and it is deliberately powerless: the
    /// suggestion is untrusted model output routed through the resilient
    /// gateway, it is **never written to authoritative state**, it holds no
    /// keys, and the founder must copy it into a real field to keep it. Only
    /// the disclosure (which provider saw Amber data) is audited.
    ///
    /// The provider is a deterministic local drafter, not an LLM. The gateway
    /// gives it health-aware failover and a data-disclosure record; Red data
    /// would never be routed to a non-local provider.
    pub fn draft_assistant(
        &self,
        customer_id: Uuid,
        lang: &str,
    ) -> Result<DraftSuggestion, WorkspaceError> {
        let workspace = self.load()?;
        let venture = workspace
            .venture
            .clone()
            .ok_or_else(|| WorkspaceError::Invalid("create the venture profile first".into()))?;
        let customer = workspace
            .customers
            .iter()
            .find(|customer| customer.id == customer_id)
            .cloned()
            .ok_or_else(|| WorkspaceError::NotFound("customer".into()))?;

        let note = draft_outreach_note(&venture, &customer, lang.starts_with("zh"));
        let gateway = ModelGateway::new(vec![
            Box::new(DeterministicProvider::local_echo(
                "local-drafter",
                ModelHealth::Healthy,
            )),
            Box::new(DeterministicProvider::local_echo(
                "local-drafter-backup",
                ModelHealth::Healthy,
            )),
        ]);
        let (response, disclosure) = gateway
            .complete(&ModelRequest {
                task: "draft_outreach".into(),
                prompt: note,
                // Business outreach about a named customer is Amber; it stays
                // local here, and would never be routed to a cloud provider.
                data_class: DataClass::Amber,
                max_output_chars: 8192,
            })
            .map_err(|error| WorkspaceError::Invalid(format!("drafting assistant: {error}")))?;

        let provider_trust = format!("{:?}", disclosure.provider_trust).to_lowercase();
        let failover_from: Vec<String> = disclosure
            .skipped
            .iter()
            .map(|entry| entry.provider_id.clone())
            .collect();

        // Persist the disclosure to the owner-visible log — never the
        // suggestion itself, only the fact that a provider saw the data.
        let entry = ModelDisclosure {
            id: Uuid::new_v4(),
            at: now(),
            customer_id,
            task: disclosure.task.clone(),
            provider_id: disclosure.provider_id.clone(),
            stayed_local: provider_trust == "local",
            provider_trust: provider_trust.clone(),
            data_class: "amber".into(),
            output_chars: disclosure.output_chars,
            failover_from: failover_from.clone(),
        };
        let mut persisted = self.load()?;
        persisted.disclosures.push(entry);
        self.save(&persisted)?;

        // Record only the disclosure — never the suggestion — as evidence.
        self.record(
            "model.drafted",
            &format!("customer:{customer_id}"),
            serde_json::json!({
                "task": disclosure.task,
                "provider": disclosure.provider_id,
                "provider_trust": provider_trust,
                "data_class": "amber",
                "output_chars": disclosure.output_chars,
                "failover_from": failover_from,
            }),
        )?;

        Ok(DraftSuggestion {
            text: response.text,
            provider_id: response.provider_id,
            provider_trust: format!("{:?}", response.provider_trust).to_lowercase(),
            saved: false,
        })
    }

    pub fn create_document(
        &self,
        kind: DocumentKind,
        customer_id: Uuid,
        amount_cents: Option<u64>,
        lang: &str,
    ) -> Result<Workspace, WorkspaceError> {
        let mut workspace = self.load()?;
        let venture = workspace
            .venture
            .clone()
            .ok_or_else(|| WorkspaceError::Invalid("create the venture profile first".into()))?;
        let customer = workspace
            .customers
            .iter()
            .find(|customer| customer.id == customer_id)
            .cloned()
            .ok_or_else(|| WorkspaceError::NotFound("customer".into()))?;
        if workspace.documents.len() >= MAX_DOCUMENTS {
            return Err(WorkspaceError::Invalid("document limit reached".into()));
        }
        if kind == DocumentKind::Invoice && amount_cents.is_none() {
            return Err(WorkspaceError::Invalid("invoice needs an amount".into()));
        }

        let operation = match kind {
            DocumentKind::Offer => "draft_offer",
            DocumentKind::Invoice => "draft_invoice",
        };
        let (allowed, _, reason) = self.check_policy(
            "document",
            operation,
            &format!("customer:{customer_id}"),
            DataClass::Amber,
            AutomationLevel::L1Draft,
        );
        if !allowed {
            return Err(WorkspaceError::PolicyDenied(reason));
        }

        let zh = lang.starts_with("zh");
        let document = render_document(kind, &venture, &customer, amount_cents, zh);
        let resource = format!("document:{}", document.id);
        let summary = serde_json::json!({
            "kind": kind,
            "title": document.title,
            "customer": customer.name,
            "amount_cents": amount_cents,
        });
        workspace.documents.push(document);
        self.save(&workspace)?;
        self.record("document.draft", &resource, summary)?;
        Ok(workspace)
    }

    /// Ask to send a document. The policy engine classifies sending as
    /// high-risk, so this never sends anything: it opens a pending approval
    /// for the human owner and records that request as evidence.
    pub fn request_send(&self, document_id: Uuid) -> Result<Workspace, WorkspaceError> {
        let mut workspace = self.load()?;
        let document = workspace
            .documents
            .iter_mut()
            .find(|document| document.id == document_id)
            .ok_or_else(|| WorkspaceError::NotFound("document".into()))?;
        if document.status != DocumentStatus::Draft {
            return Err(WorkspaceError::Invalid(
                "only drafts can be submitted".into(),
            ));
        }

        let (allowed, requires_approval, reason) = self.check_policy(
            "email",
            "send",
            &format!("document:{document_id}"),
            DataClass::Amber,
            AutomationLevel::L2ApproveExecute,
        );
        if !allowed {
            return Err(WorkspaceError::PolicyDenied(reason));
        }
        if !requires_approval {
            // Fail closed: this stage expects sending to demand approval. If
            // policy ever says otherwise, refuse rather than skip the human.
            return Err(WorkspaceError::PolicyDenied(
                "expected an approval requirement for send".into(),
            ));
        }

        document.status = DocumentStatus::PendingApproval;
        let approval = Approval {
            id: Uuid::new_v4(),
            document_id,
            action: "email.send".into(),
            policy_reason: reason,
            status: ApprovalStatus::Pending,
            requested_at: now(),
            decided_at: None,
            evidence: None,
        };
        let resource = format!("document:{document_id}");
        let summary = serde_json::json!({ "approval_id": approval.id });
        workspace.approvals.push(approval);
        self.save(&workspace)?;
        self.record("approval.requested", &resource, summary)?;
        Ok(workspace)
    }

    /// The human owner decides. Approving runs the full RFC 0003 chain: the
    /// owner's approval key signs evidence bound to one exact preparation
    /// invocation, a Capability V2 token is issued from that evidence, the
    /// pure-compute step executes in the verified Wasmtime sandbox, and the
    /// approved document is written to the local outbox through the audited
    /// broker. Any failure in the chain leaves the approval pending (fail
    /// closed); delivery to the customer stays the founder's own action.
    pub fn decide(&self, approval_id: Uuid, approve: bool) -> Result<Workspace, WorkspaceError> {
        let mut workspace = self.load()?;
        let approval = workspace
            .approvals
            .iter()
            .find(|approval| approval.id == approval_id)
            .ok_or_else(|| WorkspaceError::NotFound("approval".into()))?;
        if approval.status != ApprovalStatus::Pending {
            return Err(WorkspaceError::Invalid("approval already decided".into()));
        }
        let document_id = approval.document_id;
        let document = workspace
            .documents
            .iter()
            .find(|document| document.id == document_id)
            .cloned()
            .ok_or_else(|| WorkspaceError::NotFound("document".into()))?;

        let evidence = if approve {
            let customer = workspace
                .customers
                .iter()
                .find(|customer| customer.id == document.customer_id);
            let message = compose_email(workspace.venture.as_ref(), customer, &document);
            Some(self.execute_signed_approval(&document, message.as_bytes())?)
        } else {
            None
        };

        let approval = workspace
            .approvals
            .iter_mut()
            .find(|approval| approval.id == approval_id)
            .ok_or_else(|| WorkspaceError::NotFound("approval".into()))?;
        approval.status = if approve {
            ApprovalStatus::Approved
        } else {
            ApprovalStatus::Rejected
        };
        approval.decided_at = Some(now());
        approval.evidence = evidence.clone();
        let document_entry = workspace
            .documents
            .iter_mut()
            .find(|document| document.id == document_id)
            .ok_or_else(|| WorkspaceError::NotFound("document".into()))?;
        document_entry.status = if approve {
            DocumentStatus::ApprovedPendingDelivery
        } else {
            DocumentStatus::Rejected
        };

        self.save(&workspace)?;
        let resource = format!("document:{document_id}");
        match &evidence {
            Some(record) => {
                self.record(
                    "approval.granted",
                    &resource,
                    serde_json::json!({
                        "approval_id": approval_id,
                        "signed_approval_id": record.approval_id,
                        "evidence_digest": record.evidence_digest,
                        "approver_key_id": record.approver_key_id,
                    }),
                )?;
                self.record(
                    "capability.executed",
                    &resource,
                    serde_json::json!({
                        "tool": "workspace.delivery/prepare",
                        "component_digest": record.component_digest,
                        "canonical_input_digest": record.canonical_input_digest,
                        "idempotency": record.capability_idempotency,
                        "exit_code": record.guest_exit_code,
                        "fuel": record.fuel_consumed,
                    }),
                )?;
                if let Some(outbox) = &record.outbox {
                    self.record(
                        "effect.file_written",
                        &resource,
                        serde_json::json!({
                            "outbox_path": outbox.relative_path,
                            "content_sha256": outbox.content_sha256,
                            "bytes": outbox.bytes,
                        }),
                    )?;
                }
            }
            None => {
                self.record(
                    "approval.rejected",
                    &resource,
                    serde_json::json!({ "approval_id": approval_id, "approved": false }),
                )?;
            }
        }
        Ok(workspace)
    }

    /// Revoke an approved send: delete the composed `.eml` from the local
    /// outbox and record a signed `effect.revoked` event. This makes the
    /// "revocable" property real — the local effect is undone and the
    /// revocation is itself audited. The signed approval evidence is kept: it
    /// is history, and revoking the file does not rewrite the fact that the
    /// owner approved. Fails closed if the document is not awaiting delivery.
    pub fn revoke_delivery(&self, document_id: Uuid) -> Result<Workspace, WorkspaceError> {
        let mut workspace = self.load()?;
        let document = workspace
            .documents
            .iter()
            .find(|document| document.id == document_id)
            .ok_or_else(|| WorkspaceError::NotFound("document".into()))?;
        if document.status != DocumentStatus::ApprovedPendingDelivery {
            return Err(WorkspaceError::Invalid(
                "only an approved, undelivered document can be revoked".into(),
            ));
        }

        // Locate the outbox receipt from this document's approval evidence.
        let outbox = workspace
            .approvals
            .iter()
            .filter(|approval| approval.document_id == document_id)
            .filter_map(|approval| approval.evidence.as_ref())
            .filter_map(|evidence| evidence.outbox.as_ref())
            .next_back()
            .cloned()
            .ok_or_else(|| WorkspaceError::Invalid("no outbox effect to revoke".into()))?;

        // Delete the file. "Already gone" is an acceptable end state — the goal
        // is that the file no longer exists — but any other error fails closed.
        let broker =
            sovereign_effects::OutboxBroker::open(self.root.join("outbox")).map_err(kernel)?;
        match broker.revoke(&outbox.relative_path) {
            Ok(()) | Err(sovereign_effects::EffectError::NotFound) => {}
            Err(error) => return Err(kernel(error)),
        }

        let document_entry = workspace
            .documents
            .iter_mut()
            .find(|document| document.id == document_id)
            .ok_or_else(|| WorkspaceError::NotFound("document".into()))?;
        document_entry.status = DocumentStatus::Revoked;
        self.save(&workspace)?;

        self.record(
            "effect.revoked",
            &format!("document:{document_id}"),
            serde_json::json!({
                "outbox_path": outbox.relative_path,
                "content_sha256": outbox.content_sha256,
            }),
        )?;
        Ok(workspace)
    }

    /// Record the owner's attestation that they delivered the composed message
    /// to the customer themselves. This is deliberately honest: Stage 1 sends
    /// nothing over the network, so the system never claims to have delivered
    /// anything — it records the owner's own confirmation as a signed audit
    /// event and moves the document to `Delivered`. Fails closed unless the
    /// document is approved and awaiting delivery.
    pub fn confirm_delivery(&self, document_id: Uuid) -> Result<Workspace, WorkspaceError> {
        let mut workspace = self.load()?;
        let document = workspace
            .documents
            .iter_mut()
            .find(|document| document.id == document_id)
            .ok_or_else(|| WorkspaceError::NotFound("document".into()))?;
        if document.status != DocumentStatus::ApprovedPendingDelivery {
            return Err(WorkspaceError::Invalid(
                "only an approved, undelivered document can be confirmed delivered".into(),
            ));
        }
        document.status = DocumentStatus::Delivered;
        self.save(&workspace)?;
        self.record(
            "delivery.confirmed",
            &format!("document:{document_id}"),
            serde_json::json!({ "attested_by": "founder", "system_sent": false }),
        )?;
        Ok(workspace)
    }
}
