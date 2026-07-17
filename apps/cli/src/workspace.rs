//! Minimal Founder Workspace: the first *usable* slice of the product.
//!
//! This is a deliberately small, deterministic prototype of the future
//! Sovereign Enterprise Graph and Approval Center. It already honors the
//! architecture's non-negotiables where they exist today:
//!
//! - authoritative state lives in the local encrypted vault, never in a cloud
//!   or a chat history;
//! - every mutation is evaluated by the deterministic policy engine first and
//!   leaves a signed, hash-chained audit event;
//! - actions the policy classifies as high-risk (sending a document) are not
//!   executed on the model's say-so: they enter a pending-approval queue for
//!   the human owner, and only the owner's signed approval unlocks the effect;
//! - the founder can export every byte of their business state at any time.
//!
//! Honest labels: documents are template-generated and the graph schema is a
//! prototype. A local drafting assistant (deterministic, not an LLM) can
//! suggest outreach text through the resilient model gateway, but its output
//! is untrusted, is never written to authoritative state, and holds no keys —
//! only the disclosure is audited. Approving a send runs the real RFC
//! 0003 chain — owner-signed approval evidence, a Capability V2 token issued
//! from it, a pure-compute preparation step in the verified sandbox, and then
//! the first real host effect: the approved document is written to the local
//! `outbox/` directory through an audited, path-safe broker. That local file
//! write is genuine and revocable; delivering the file to the customer
//! remains the founder's own action, and no network effect exists. Owner keys
//! live in the prototype vault.

use std::path::{Path, PathBuf};

use chrono::Duration as ChronoDuration;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sovereign_artifact::{
    ArtifactStore, ArtifactVerificationIntent, ArtifactVerifier, Digest, OperationSelector,
    PreparedInvocation, RawResourceGrant, SystemClock as ArtifactClock, MANIFEST_PROTOCOL_VERSION,
};
use sovereign_audit_ledger::{hash_bytes, AppendInput, AuditLedger};
use sovereign_capability::approval::{approve_invocation, ApprovalClaimsV1, ApprovalGrantRequest};
use sovereign_capability::v2::{
    CapabilityIssuerV2, CapabilityV2IssueOptions, CapabilityV2IssueRequest, CapabilityValidatorV2,
    SystemClock as CapabilityClock,
};
use sovereign_contracts::{ActionRequest, AuditEvent, AutomationLevel, DataClass};
use sovereign_identity::{
    device_id_from_public_key_b64, AdmissionRole, ApprovalRole, AuthorityRole, DeviceIdentity,
    KeyValidity, PublisherRole, RoleTrustStore, TypedSigner,
};
use sovereign_model::{DeterministicProvider, Health as ModelHealth, ModelGateway, ModelRequest};
use sovereign_policy::{AuthenticatedPolicyContextV2, PolicyEngine};
use sovereign_sandbox::{VerifiedExecutionRequest, VerifiedSandboxExecutor};
use sovereign_vault::Vault;
use uuid::Uuid;

use crate::demo::compile_wat;

pub const WORKSPACE_VAULT_ENTRY: &str = "workspace_graph";
const WORKSPACE_VERSION: u32 = 1;
/// Stable identifier stamped into every export and required on verification.
pub const EXPORT_FORMAT: &str = "sovereign-founder-os-export";
const MAX_TEXT_FIELD_BYTES: usize = 4 * 1024;
const MAX_CUSTOMERS: usize = 500;
const MAX_DOCUMENTS: usize = 2_000;

// The built-in delivery-preparation tool is authored by the application
// itself; its publisher key is a build constant, not a secret. Owner keys
// (approval, authority, admission) are generated per installation and kept
// in the encrypted vault — prototype key management, honestly labelled.
const BUILTIN_PUBLISHER_SECRET: [u8; 32] = *b"sovereign-builtin-publisher-01!!";
const BUILTIN_PUBLISHER_ISSUER: &str = "builtin.sovereign-founder-os";
const RUNTIME_AUTHORITY_ISSUER: &str = "workspace-runtime.local";
const OWNER_APPROVAL_ISSUER: &str = "founder-owner.local";
const OWNER_ADMISSION_ISSUER: &str = "founder-device.workspace";
const WORKSPACE_AUDIENCE: &str = "sovereign-runtime";
const APPROVAL_TTL_SECONDS: i64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("{0}")]
    Invalid(String),
    #[error("policy denied the action: {0}")]
    PolicyDenied(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("storage error: {0}")]
    Storage(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Venture {
    pub name: String,
    pub service: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customer {
    pub id: Uuid,
    pub name: String,
    /// Optional contact address. When present, a composed outreach email
    /// addresses it directly; when empty, the email uses an RFC 2606
    /// placeholder the founder must replace before sending. Defaulted so
    /// vaults written before this field deserialize unchanged.
    #[serde(default)]
    pub email: String,
    pub notes: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentKind {
    Offer,
    Invoice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentStatus {
    Draft,
    PendingApproval,
    ApprovedPendingDelivery,
    Rejected,
    /// An approved send whose composed outbox file the owner later revoked.
    /// The signed approval evidence remains; the local effect was undone and
    /// the revocation is itself audited.
    Revoked,
    /// The owner has attested they delivered the composed message to the
    /// customer themselves. Stage 1 sends nothing over the network — this is a
    /// human attestation, recorded as a signed audit event, not a system send.
    Delivered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: Uuid,
    pub kind: DocumentKind,
    pub customer_id: Uuid,
    pub title: String,
    pub body: String,
    pub amount_cents: Option<u64>,
    pub status: DocumentStatus,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: Uuid,
    pub document_id: Uuid,
    pub action: String,
    pub policy_reason: String,
    pub status: ApprovalStatus,
    pub requested_at: i64,
    pub decided_at: Option<i64>,
    /// RFC 0003 evidence recorded when the owner approves. Absent on
    /// rejections and on approvals from before this protocol existed.
    #[serde(default)]
    pub evidence: Option<SignedApprovalRecord>,
}

/// Portable record of one signed approval and the sandboxed execution it
/// authorized. The full COSE bytes are kept (hex) so the evidence can be
/// re-verified independently after export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedApprovalRecord {
    pub approval_id: Uuid,
    pub approver_subject_id: String,
    pub approver_key_id: String,
    pub evidence_digest: String,
    pub signed_approval_hex: String,
    pub component_digest: String,
    pub canonical_input_digest: String,
    pub capability_idempotency: Uuid,
    pub guest_exit_code: i32,
    pub fuel_consumed: u64,
    /// The real host effect performed after authorization: the approved
    /// document written to the local outbox. Absent only if this record
    /// predates the outbox effect.
    #[serde(default)]
    pub outbox: Option<OutboxWrite>,
}

/// Receipt for the audited local file the runtime actually wrote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxWrite {
    pub relative_path: String,
    pub content_sha256: String,
    pub bytes: usize,
}

/// An untrusted model suggestion. `saved` is always false: the assistant never
/// writes authoritative state, so the founder must copy this into a real field
/// for it to persist. It carries no authority and no keys.
#[derive(Debug, Clone, Serialize)]
pub struct DraftSuggestion {
    pub text: String,
    pub provider_id: String,
    pub provider_trust: String,
    pub saved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Workspace {
    pub version: u32,
    pub venture: Option<Venture>,
    pub customers: Vec<Customer>,
    pub documents: Vec<Document>,
    pub approvals: Vec<Approval>,
}

/// At-a-glance product view: the founder's whole business plus the security
/// evidence that backs it, derived purely from stored state. It is read-only
/// and adds no new claims — it only surfaces what the workspace already proved.
#[derive(Debug, Clone, Serialize)]
pub struct CommandCenter {
    pub venture: Option<Venture>,
    pub counts: CommandCenterCounts,
    /// Approvals still waiting on the owner — the only actionable items here.
    pub pending_decisions: Vec<PendingDecision>,
    pub evidence: EvidenceRollup,
    /// Deterministic next steps and risks read straight from state — ordered
    /// most-important first. These are observations, not predictions: no model
    /// is involved, and the same state always yields the same list.
    pub guidance: Vec<Guidance>,
}

/// One suggested next step or surfaced risk. `kind` is a stable machine code
/// the UI localizes; `count`/`subject` fill in its parameters.
#[derive(Debug, Clone, Serialize)]
pub struct Guidance {
    pub kind: String,
    /// "action" (something to do) or "risk" (something to be aware of).
    pub kind_class: String,
    pub count: usize,
    pub subject: String,
}

impl Guidance {
    fn action(kind: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            kind_class: "action".to_owned(),
            count: 0,
            subject: String::new(),
        }
    }
    fn with_count(mut self, count: usize) -> Self {
        self.count = count;
        self
    }
    fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }
    fn risk(kind: &str) -> Self {
        Self {
            kind_class: "risk".to_owned(),
            ..Self::action(kind)
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandCenterCounts {
    pub customers: usize,
    pub documents: usize,
    pub drafts: usize,
    pub pending_approval: usize,
    pub approved_pending_delivery: usize,
    pub rejected: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingDecision {
    pub approval_id: Uuid,
    pub document_id: Uuid,
    pub document_title: String,
    pub customer_name: String,
    pub action: String,
    pub policy_reason: String,
    pub requested_at: i64,
}

/// Counts of the tamper-evident evidence already on disk. These are facts the
/// owner can re-verify from the export, not aspirational security claims.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceRollup {
    /// Approvals carrying RFC 0003 signed evidence.
    pub signed_approvals: usize,
    /// Approvals whose sandboxed execution wrote a real audited outbox file.
    pub outbox_effects: usize,
    /// Relative path of the most recent real host effect, if any.
    pub last_effect_path: Option<String>,
}

/// The result of independently verifying an exported bundle, offline. Every
/// field is derived from the bundle alone — no device, vault, or network — so
/// anyone the founder hands the file to can confirm it is intact and authentic.
#[derive(Debug, Clone, Serialize)]
pub struct ExportVerification {
    pub format_ok: bool,
    pub version: u64,
    pub device_id: String,
    /// The declared `device_id` equals the fingerprint of the key that signed
    /// the audit events — the history is cryptographically bound to that id.
    pub identity_bound: bool,
    pub audit_events: usize,
    /// The full signed hash chain recomputes and every Ed25519 signature checks.
    pub audit_chain_verified: bool,
    pub customers: usize,
    pub documents: usize,
    pub signed_approvals: usize,
    /// Well-formed, identity-bound, and chain-verified. Anything less is
    /// surfaced in `notes`, never silently downgraded to a pass.
    pub ok: bool,
    /// Human-readable explanation of any check that did not pass.
    pub notes: Vec<String>,
}

/// Storage + evidence context for one workspace operation.
pub struct Store {
    root: PathBuf,
    device: DeviceIdentity,
    policy: PolicyEngine,
}

impl Store {
    pub fn open(root: &Path) -> Result<Self, WorkspaceError> {
        std::fs::create_dir_all(root).map_err(storage)?;
        let device_path = root.join("device.json");
        let device = if device_path.exists() {
            DeviceIdentity::load(&device_path).map_err(storage)?
        } else {
            let device = DeviceIdentity::generate();
            device.save(&device_path).map_err(storage)?;
            device
        };
        Ok(Self {
            root: root.to_path_buf(),
            device,
            policy: PolicyEngine::new(),
        })
    }

    pub fn load(&self) -> Result<Workspace, WorkspaceError> {
        let vault = Vault::init(self.root.join("vault")).map_err(storage)?;
        match vault.get(WORKSPACE_VAULT_ENTRY) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| WorkspaceError::Storage(format!("corrupt workspace: {error}"))),
            Err(sovereign_vault::VaultError::NotFound(_)) => Ok(Workspace {
                version: WORKSPACE_VERSION,
                ..Workspace::default()
            }),
            Err(error) => Err(storage(error)),
        }
    }

    fn save(&self, workspace: &Workspace) -> Result<(), WorkspaceError> {
        let mut vault = Vault::init(self.root.join("vault")).map_err(storage)?;
        let bytes = serde_json::to_vec(workspace).map_err(storage)?;
        vault.put(WORKSPACE_VAULT_ENTRY, &bytes).map_err(storage)?;
        Ok(())
    }

    /// Evaluate policy for a workflow action; deny fails closed, and both
    /// allowed and denied evaluations can be audited by the caller.
    fn check_policy(
        &self,
        tool: &str,
        operation: &str,
        resource: &str,
        data_class: DataClass,
        automation_level: AutomationLevel,
    ) -> (bool, bool, String) {
        let decision = self.policy.evaluate(ActionRequest {
            actor_id: "founder".into(),
            venture_id: "workspace".into(),
            tool: tool.into(),
            operation: operation.into(),
            resource: resource.into(),
            data_class,
            automation_level,
        });
        (
            decision.allowed,
            decision.requires_approval,
            decision.reason,
        )
    }

    fn record(
        &self,
        action: &str,
        resource: &str,
        payload: serde_json::Value,
    ) -> Result<(), WorkspaceError> {
        let ledger_path = self.root.join("ledger.json");
        let mut ledger = if ledger_path.exists() {
            AuditLedger::load(&ledger_path, self.device.public_key_b64()).map_err(storage)?
        } else {
            AuditLedger::new()
        };
        let payload_digest = hash_bytes(&serde_json::to_vec(&payload).map_err(storage)?);
        ledger
            .append(
                AppendInput {
                    venture_id: "workspace".into(),
                    actor_id: "founder".into(),
                    action: action.into(),
                    resource: resource.into(),
                    capability_id: None,
                    payload: serde_json::json!({
                        "summary": payload,
                        "payload_digest": payload_digest,
                    }),
                    policy_decision_hash: None,
                },
                &self.device,
            )
            .map_err(storage)?;
        ledger.save(&ledger_path).map_err(storage)?;
        Ok(())
    }

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

        // Record only the disclosure — never the suggestion — as evidence.
        self.record(
            "model.drafted",
            &format!("customer:{customer_id}"),
            serde_json::json!({
                "task": disclosure.task,
                "provider": disclosure.provider_id,
                "provider_trust": format!("{:?}", disclosure.provider_trust).to_lowercase(),
                "data_class": "amber",
                "output_chars": disclosure.output_chars,
                "failover_from": disclosure
                    .skipped
                    .iter()
                    .map(|entry| entry.provider_id.clone())
                    .collect::<Vec<_>>(),
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

    /// One end-to-end pass of the secure kernel, triggered by the owner's
    /// click: verify the built-in delivery-preparation plugin, admit it into
    /// the local store, prepare the exact invocation for this document, get a
    /// deterministic policy decision (which demands approval), sign RFC 0003
    /// evidence with the owner's approval key, issue a Capability V2 token
    /// from that evidence, and execute the pure-compute step in the verified
    /// sandbox. Every stage fails closed.
    fn execute_signed_approval(
        &self,
        document: &Document,
        delivery: &[u8],
    ) -> Result<SignedApprovalRecord, WorkspaceError> {
        let approval_secret = self.owner_secret("owner_approval_key")?;
        let authority_secret = self.owner_secret("runtime_authority_key")?;
        let admission_secret = self.owner_secret("owner_admission_key")?;

        let now_unix = now();
        let validity = KeyValidity::new(now_unix - 60, now_unix + 3_600).map_err(kernel)?;

        // Built-in delivery-preparation tool: publisher-verified, then
        // admitted under the owner's admission key (or reloaded and
        // re-verified from the content-addressed store on later runs).
        let component =
            compile_wat(r#"(module (func (export "sovereign_run") (result i32) i32.const 0))"#);
        let publisher = TypedSigner::<PublisherRole>::from_secret_bytes(
            BUILTIN_PUBLISHER_ISSUER,
            BUILTIN_PUBLISHER_SECRET,
        )
        .map_err(kernel)?;
        let manifest = delivery_manifest_json(&publisher, &component);
        let canonical_manifest = serde_json_canonicalizer::to_vec(&manifest).map_err(kernel)?;
        let signed_manifest = publisher.sign_cose(&canonical_manifest).map_err(kernel)?;
        let mut publishers = RoleTrustStore::<PublisherRole>::new();
        publishers
            .trust_signer(&publisher, validity)
            .map_err(kernel)?;
        let intent = ArtifactVerificationIntent::new(
            BUILTIN_PUBLISHER_ISSUER,
            Digest::of_bytes(&signed_manifest),
            Digest::of_bytes(&component),
        )
        .map_err(kernel)?;
        let artifact = ArtifactVerifier::new(&publishers)
            .verify(&intent, &signed_manifest, &component)
            .map_err(kernel)?;

        let admission_signer = TypedSigner::<AdmissionRole>::from_secret_bytes(
            OWNER_ADMISSION_ISSUER,
            admission_secret,
        )
        .map_err(kernel)?;
        let mut admission_trust = RoleTrustStore::<AdmissionRole>::new();
        admission_trust
            .trust_signer(&admission_signer, validity)
            .map_err(kernel)?;
        let store = ArtifactStore::open(self.root.join("artifacts")).map_err(kernel)?;
        let admitted = match store.admit(&artifact, &admission_signer, &ArtifactClock) {
            Ok(admitted) => admitted,
            Err(sovereign_artifact::ArtifactError::AdmissionRecordExists) => store
                .load(
                    artifact.component_digest(),
                    artifact.manifest_digest(),
                    &admission_trust,
                    OWNER_ADMISSION_ISSUER,
                    &ArtifactClock,
                )
                .map_err(kernel)?,
            Err(error) => return Err(kernel(error)),
        };

        let selector =
            OperationSelector::new("workspace.delivery", "1.0.0", "prepare").map_err(kernel)?;
        let resource = format!("document:{}", document.id);
        let input = serde_json::to_vec(&serde_json::json!({
            "document_id": document.id.to_string(),
            "resource": resource,
        }))
        .map_err(kernel)?;
        let invocation = PreparedInvocation::prepare(
            admitted.artifact(),
            &selector,
            &input,
            vec![RawResourceGrant::new("primary", resource.as_str())],
        )
        .map_err(kernel)?;

        let session_id = Uuid::new_v4();
        let idempotency = Uuid::new_v4();
        let decision = PolicyEngine::new()
            .evaluate_prepared(
                &invocation,
                AuthenticatedPolicyContextV2::new(
                    WORKSPACE_AUDIENCE,
                    "workspace",
                    "founder",
                    session_id,
                    DataClass::Amber,
                    AutomationLevel::L2ApproveExecute,
                    idempotency,
                )
                .map_err(kernel)?,
            )
            .map_err(kernel)?;
        if !decision.allowed() {
            return Err(WorkspaceError::PolicyDenied(
                "delivery preparation denied by policy".into(),
            ));
        }
        if !decision.requires_approval() {
            // Fail closed: this path exists precisely because policy demands
            // a human; if it ever stops demanding one, refuse to proceed.
            return Err(WorkspaceError::PolicyDenied(
                "expected an approval requirement for delivery".into(),
            ));
        }

        let approval_signer =
            TypedSigner::<ApprovalRole>::from_secret_bytes(OWNER_APPROVAL_ISSUER, approval_secret)
                .map_err(kernel)?;
        let signed_approval = approve_invocation(
            &approval_signer,
            &CapabilityClock,
            ApprovalGrantRequest {
                approver_subject_id: "founder-owner",
                audience: WORKSPACE_AUDIENCE,
                venture_id: "workspace",
                subject_id: "founder",
                session_id,
                policy_decision: &decision,
                prepared_invocation: &invocation,
                ttl_seconds: APPROVAL_TTL_SECONDS,
            },
        )
        .map_err(kernel)?;
        let mut approval_trust = RoleTrustStore::<ApprovalRole>::new();
        approval_trust
            .trust_signer(&approval_signer, validity)
            .map_err(kernel)?;
        // Extract the claims for the audit record by verifying our own
        // evidence exactly the way the issuer will.
        let approval_claims: ApprovalClaimsV1 = serde_json::from_slice(
            approval_trust
                .verify(signed_approval.as_bytes(), OWNER_APPROVAL_ISSUER, now())
                .map_err(kernel)?
                .payload(),
        )
        .map_err(kernel)?;

        let authority = TypedSigner::<AuthorityRole>::from_secret_bytes(
            RUNTIME_AUTHORITY_ISSUER,
            authority_secret,
        )
        .map_err(kernel)?;
        let mut authority_trust = RoleTrustStore::<AuthorityRole>::new();
        authority_trust
            .trust_signer(&authority, validity)
            .map_err(kernel)?;
        let mut approval_trust_for_validator = RoleTrustStore::<ApprovalRole>::new();
        approval_trust_for_validator
            .trust_signer(&approval_signer, validity)
            .map_err(kernel)?;

        let issuer = CapabilityIssuerV2::new(authority, WORKSPACE_AUDIENCE, CapabilityClock)
            .map_err(kernel)?
            .with_approval_trust(approval_trust, OWNER_APPROVAL_ISSUER)
            .map_err(kernel)?;
        let token = issuer
            .issue_approved(
                CapabilityV2IssueRequest {
                    venture_id: "workspace",
                    subject_id: "founder",
                    session_id,
                    policy_decision: &decision,
                    prepared_invocation: &invocation,
                    options: CapabilityV2IssueOptions {
                        ttl: ChronoDuration::seconds(60),
                        idempotency_key: idempotency,
                    },
                },
                &signed_approval,
            )
            .map_err(kernel)?;

        let validator = CapabilityValidatorV2::new(
            authority_trust,
            RUNTIME_AUTHORITY_ISSUER,
            WORKSPACE_AUDIENCE,
            CapabilityClock,
        )
        .map_err(kernel)?
        .with_approval_trust(approval_trust_for_validator, OWNER_APPROVAL_ISSUER)
        .map_err(kernel)?
        .with_authority_store(
            sovereign_authority::AuthorityStore::open(self.root.join("authority"))
                .map_err(kernel)?,
        );
        let mut executor = VerifiedSandboxExecutor::new(vec![selector], validator)
            .map_err(kernel)?
            .with_execution_journal(
                sovereign_execution::ExecutionJournal::open(self.root.join("executions"))
                    .map_err(kernel)?,
            );
        let result = executor
            .execute_approved(
                VerifiedExecutionRequest {
                    token: &token,
                    invocation: &invocation,
                    venture_id: "workspace",
                    subject_id: "founder",
                    session_id,
                    policy_decision: &decision,
                },
                Some(&signed_approval),
            )
            .map_err(kernel)?;

        // The first real host effect: with the whole chain verified and the
        // capability durably consumed, write the composed outreach message to
        // the owner's local outbox as an RFC 5322 `.eml`. This is audited and
        // revocable; the message is composed, not transmitted — delivery to the
        // customer remains the founder's own action.
        let outbox =
            sovereign_effects::OutboxBroker::open(self.root.join("outbox")).map_err(kernel)?;
        let receipt = outbox
            .write_message(
                &document.id.simple().to_string(),
                sovereign_effects::EffectDataClass::Amber,
                delivery,
            )
            .map_err(kernel)?;

        Ok(SignedApprovalRecord {
            approval_id: approval_claims.approval_id,
            approver_subject_id: approval_claims.approver_subject_id,
            approver_key_id: approval_claims.approver_key_id.as_hex(),
            evidence_digest: hash_bytes(signed_approval.as_bytes()),
            signed_approval_hex: hex::encode(signed_approval.as_bytes()),
            component_digest: invocation.artifact().component_digest().as_hex(),
            canonical_input_digest: invocation.input_digest().as_hex(),
            capability_idempotency: idempotency,
            guest_exit_code: result.exit_code,
            fuel_consumed: result.fuel_consumed,
            outbox: Some(OutboxWrite {
                relative_path: receipt.relative_path,
                content_sha256: receipt.content_sha256_hex,
                bytes: receipt.bytes,
            }),
        })
    }

    /// Load or create one of the owner's 32-byte signing secrets, stored in
    /// the encrypted vault. Prototype key management: the vault key itself is
    /// a local file in this stage.
    fn owner_secret(&self, name: &str) -> Result<[u8; 32], WorkspaceError> {
        let mut vault = Vault::init(self.root.join("vault")).map_err(storage)?;
        match vault.get(name) {
            Ok(bytes) => bytes
                .try_into()
                .map_err(|_| WorkspaceError::Storage(format!("corrupt key entry `{name}`"))),
            Err(sovereign_vault::VaultError::NotFound(_)) => {
                let mut secret = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut secret);
                vault.put(name, &secret).map_err(storage)?;
                Ok(secret)
            }
            Err(error) => Err(storage(error)),
        }
    }

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

/// Verify an exported bundle independently and offline. Pure over its input:
/// it opens no store, loads no keys, and touches no network, so it can check a
/// backup on any machine. When `ok` is true the bundle is well-formed, its
/// audit history is bound to the `device_id` it declares, and the entire signed
/// hash chain re-verifies. Any failure is reported in `notes`, never hidden.
pub fn verify_export(bundle: &serde_json::Value) -> Result<ExportVerification, WorkspaceError> {
    let mut notes = Vec::new();

    let format = bundle
        .get("format")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let format_ok = format == EXPORT_FORMAT;
    if !format_ok {
        notes.push(format!("unexpected format tag: {format:?}"));
    }
    let version = bundle
        .get("version")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let device_id = bundle
        .get("device_id")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_owned();

    let events: Vec<AuditEvent> = match bundle.get("audit_events") {
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|error| WorkspaceError::Invalid(format!("audit_events malformed: {error}")))?,
        None => Vec::new(),
    };
    let audit_events = events.len();

    // Identity binding and full-chain verification, from the events alone. Each
    // event embeds the signing public key, so the chain — hash linkage and
    // Ed25519 signatures — is checkable without any external key material.
    let (identity_bound, audit_chain_verified) = if events.is_empty() {
        (false, true)
    } else {
        let signing_key = events[0].device_public_key_b64.clone();
        let uniform_key = events
            .iter()
            .all(|event| event.device_public_key_b64 == signing_key);
        if !uniform_key {
            notes.push("audit events are signed by more than one key".into());
        }
        let identity_bound = match device_id_from_public_key_b64(&signing_key) {
            Ok(expected) if expected == device_id => true,
            Ok(_) => {
                notes.push("device_id does not match the audit-signing key".into());
                false
            }
            Err(error) => {
                notes.push(format!("audit-signing key is invalid: {error}"));
                false
            }
        };
        let chain_ok = match AuditLedger::from_events(events, signing_key) {
            Ok(_) => true,
            Err(error) => {
                notes.push(format!("audit chain failed verification: {error}"));
                false
            }
        };
        (identity_bound && uniform_key, chain_ok)
    };

    let workspace = bundle.get("workspace");
    let array_len = |key: &str| {
        workspace
            .and_then(|value| value.get(key))
            .and_then(|value| value.as_array())
            .map(|array| array.len())
            .unwrap_or(0)
    };
    let customers = array_len("customers");
    let documents = array_len("documents");
    let signed_approvals = workspace
        .and_then(|value| value.get("approvals"))
        .and_then(|value| value.as_array())
        .map(|approvals| {
            approvals
                .iter()
                .filter(|approval| {
                    approval
                        .get("evidence")
                        .map(|evidence| !evidence.is_null())
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0);

    let ok = if audit_events == 0 {
        notes.push("no audit history in this bundle — nothing to cryptographically verify".into());
        format_ok
    } else {
        format_ok && identity_bound && audit_chain_verified
    };

    Ok(ExportVerification {
        format_ok,
        version,
        device_id,
        identity_bound,
        audit_events,
        audit_chain_verified,
        customers,
        documents,
        signed_approvals,
        ok,
        notes,
    })
}

fn delivery_manifest_json(
    publisher: &TypedSigner<PublisherRole>,
    component: &[u8],
) -> serde_json::Value {
    serde_json::json!({
        "protocol_version": MANIFEST_PROTOCOL_VERSION,
        "publisher_issuer": BUILTIN_PUBLISHER_ISSUER,
        "publisher_key_id": Digest::from_bytes(*publisher.key_id()),
        "component_digest": Digest::of_bytes(component),
        "backend": "core_wasm",
        "risk_class": "pure_compute",
        "abi": "sovereign_core_wasm_v1",
        "entrypoint": sovereign_artifact::CORE_WASM_ENTRYPOINT,
        "requested_host_capabilities": [],
        "operations": [{
            "selector": {
                "tool_id": "workspace.delivery",
                "tool_version": "1.0.0",
                "operation_id": "prepare"
            },
            "input_limits": { "max_bytes": 2048, "max_depth": 4 },
            "input_schema": {
                "type": "object",
                "properties": {
                    "document_id": { "type": "string", "max_utf8_bytes": 64 },
                    "resource": { "type": "string", "max_utf8_bytes": 128 }
                },
                "required": ["document_id", "resource"],
                "max_properties": 2
            },
            "resource_bindings": [{
                "binding_id": "primary",
                "json_pointer": "/resource",
                "normalization": "exact_utf8_v1",
                "primary": true
            }]
        }]
    })
}

fn kernel(error: impl std::fmt::Display) -> WorkspaceError {
    WorkspaceError::Storage(format!("kernel chain failed closed: {error}"))
}

fn draft_outreach_note(venture: &Venture, customer: &Customer, zh: bool) -> String {
    // Deterministic local drafting logic — this is the "assistant" content.
    // It composes from known facts only; it invents nothing and cites no
    // numbers, so an unreviewed copy is safe.
    if zh {
        format!(
            "你好 {customer},\n\n我是 {venture} 的负责人。{service}——如果这正是你们现在需要的,我很乐意约个简短的通话,聊聊你们的目标和时间安排。\n\n期待回音。\n\n(本地起草助手草拟 · 未保存 · 请审阅后再使用)",
            customer = customer.name,
            venture = venture.name,
            service = venture.service,
        )
    } else {
        format!(
            "Hi {customer},\n\nI'm the founder of {venture}. {service} — if that's useful to you right now, I'd be glad to set up a short call to understand your goals and timeline.\n\nLooking forward to hearing from you.\n\n(drafted by the local assistant · not saved · review before use)",
            customer = customer.name,
            venture = venture.name,
            service = venture.service,
        )
    }
}

fn render_document(
    kind: DocumentKind,
    venture: &Venture,
    customer: &Customer,
    amount_cents: Option<u64>,
    zh: bool,
) -> Document {
    // Deterministic templates by design: no model output enters authoritative
    // business state in this stage.
    let (title, body) = match (kind, zh) {
        (DocumentKind::Offer, false) => (
            format!("Offer — {} for {}", venture.name, customer.name),
            format!(
                "OFFER (DRAFT)\n\nFrom: {}\nTo: {}\n\nProposed service:\n{}\n\nScope, timeline, and pricing to be confirmed together.\nThis draft was generated locally by Sovereign Founder OS; no model was involved and nothing has been sent.",
                venture.name, customer.name, venture.service
            ),
        ),
        (DocumentKind::Offer, true) => (
            format!("报价单 — {} 致 {}", venture.name, customer.name),
            format!(
                "报价单(草稿)\n\n发件方:{}\n客户:{}\n\n拟提供的服务:\n{}\n\n范围、周期与价格待双方确认。\n本草稿由 Sovereign Founder OS 在本地生成;未使用任何模型,也未发送给任何人。",
                venture.name, customer.name, venture.service
            ),
        ),
        (DocumentKind::Invoice, false) => (
            format!("Invoice — {} to {}", venture.name, customer.name),
            format!(
                "INVOICE (DRAFT)\n\nFrom: {}\nBill to: {}\nAmount: {}\n\nPayment terms to be confirmed.\nThis draft was generated locally by Sovereign Founder OS and has not been issued.",
                venture.name,
                customer.name,
                format_amount(amount_cents.unwrap_or(0)),
            ),
        ),
        (DocumentKind::Invoice, true) => (
            format!("发票草稿 — {} 致 {}", venture.name, customer.name),
            format!(
                "发票(草稿)\n\n开票方:{}\n客户:{}\n金额:{}\n\n付款条款待确认。\n本草稿由 Sovereign Founder OS 在本地生成,尚未开具。",
                venture.name,
                customer.name,
                format_amount(amount_cents.unwrap_or(0)),
            ),
        ),
    };
    Document {
        id: Uuid::new_v4(),
        kind,
        customer_id: customer.id,
        title,
        body,
        amount_cents,
        status: DocumentStatus::Draft,
        created_at: now(),
    }
}

fn format_amount(cents: u64) -> String {
    format!("$ {}.{:02}", cents / 100, cents % 100)
}

/// Parse a decimal money string ("2500", "2500.5", "2500.50") into cents
/// without floating point.
pub fn parse_amount_cents(text: &str) -> Result<u64, WorkspaceError> {
    let text = text.trim();
    let invalid = || WorkspaceError::Invalid("invalid amount".into());
    if text.is_empty() || text.len() > 16 {
        return Err(invalid());
    }
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (text, ""),
    };
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 2
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    let whole: u64 = whole.parse().map_err(|_| invalid())?;
    let fraction_cents = match fraction.len() {
        0 => 0,
        1 => fraction.parse::<u64>().map_err(|_| invalid())? * 10,
        _ => fraction.parse::<u64>().map_err(|_| invalid())?,
    };
    whole
        .checked_mul(100)
        .and_then(|cents| cents.checked_add(fraction_cents))
        .ok_or_else(invalid)
}

fn clean_text(field: &str, value: &str) -> Result<String, WorkspaceError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(WorkspaceError::Invalid(format!("{field} is required")));
    }
    clean_optional_text(field, value)
}

fn clean_optional_text(field: &str, value: &str) -> Result<String, WorkspaceError> {
    let value = value.trim();
    if value.len() > MAX_TEXT_FIELD_BYTES {
        return Err(WorkspaceError::Invalid(format!("{field} is too long")));
    }
    if value.chars().any(|ch| ch.is_control() && ch != '\n') {
        return Err(WorkspaceError::Invalid(format!(
            "{field} contains control characters"
        )));
    }
    Ok(value.to_owned())
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

/// Compose a well-formed RFC 5322 message for an approved document. The result
/// is written to the local outbox and never transmitted — an `X-Sovereign`
/// header says so, and a missing recipient becomes an RFC 2606 `.invalid`
/// placeholder the founder must replace before sending. Header values come from
/// validated fields (names carry no control characters, emails no CR/LF or
/// separators), and are re-sanitized here, so no field can inject a header.
fn compose_email(
    venture: Option<&Venture>,
    customer: Option<&Customer>,
    document: &Document,
) -> String {
    let sender_name = venture
        .map(|venture| venture.name.as_str())
        .unwrap_or("Sovereign Founder");
    let recipient_name = customer
        .map(|customer| customer.name.as_str())
        .unwrap_or("Customer");
    let recipient_addr = customer
        .map(|customer| customer.email.trim())
        .filter(|email| !email.is_empty())
        .map(|email| email.to_owned())
        .unwrap_or_else(|| "recipient@example.invalid".to_owned());
    let placeholder = recipient_addr.ends_with(".invalid");

    let mut message = String::new();
    message.push_str(&format!(
        "From: {} <founder@example.invalid>\r\n",
        encode_display_name(sender_name)
    ));
    message.push_str(&format!(
        "To: {} <{}>\r\n",
        encode_display_name(recipient_name),
        header_safe(&recipient_addr)
    ));
    message.push_str(&format!("Subject: {}\r\n", header_safe(&document.title)));
    message.push_str(&format!("Date: {}\r\n", chrono::Utc::now().to_rfc2822()));
    message.push_str(&format!(
        "Message-ID: <{}@sovereign-founder-os.invalid>\r\n",
        document.id.simple()
    ));
    message.push_str("MIME-Version: 1.0\r\n");
    message.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    message.push_str(
        "X-Sovereign-Composed: composed locally by Sovereign Founder OS; not transmitted\r\n",
    );
    if placeholder {
        message.push_str(
            "X-Sovereign-Note: recipient address is a placeholder — set the customer's email before sending\r\n",
        );
    }
    message.push_str("\r\n");
    for line in document.body.split('\n') {
        message.push_str(line.trim_end_matches('\r'));
        message.push_str("\r\n");
    }
    message
}

/// Render an RFC 5322 display-name: kept bare when it is a safe atom, otherwise
/// a quoted-string with `\\` and `"` escaped. CR/LF are stripped defensively.
fn encode_display_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .filter(|ch| *ch != '\r' && *ch != '\n')
        .collect();
    let needs_quoting = sanitized.is_empty()
        || sanitized
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || " !#$%&'*+-/=?^_`{|}~".contains(ch)));
    if needs_quoting {
        let escaped = sanitized.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        sanitized
    }
}

/// Collapse any CR/LF in a single-line header value to spaces — defense in
/// depth against header injection on top of upstream field validation.
fn header_safe(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

/// Validate an optional contact email. Empty is allowed (the founder can add
/// it later). A non-empty value must be a single-line, single-`@` address with
/// no spaces or header-injection characters — enough to place safely in an
/// RFC 5322 `To:` header without claiming full RFC 5321 validation.
fn clean_email(value: &str) -> Result<String, WorkspaceError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.len() > 254 {
        return Err(WorkspaceError::Invalid("email is too long".into()));
    }
    let at_count = value.bytes().filter(|byte| *byte == b'@').count();
    let structural =
        at_count == 1 && !value.starts_with('@') && !value.ends_with('@') && value.contains('.');
    let no_injection = value
        .bytes()
        .all(|byte| !byte.is_ascii_control() && !matches!(byte, b' ' | b'\t' | b',' | b'<' | b'>'));
    if !structural || !no_injection {
        return Err(WorkspaceError::Invalid(
            "email is not a valid address".into(),
        ));
    }
    Ok(value.to_owned())
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn storage(error: impl std::fmt::Display) -> WorkspaceError {
    WorkspaceError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
    fn draft_assistant_never_touches_authoritative_state() {
        let (_dir, store) = store();
        store.set_venture("Acme", "Landing pages").unwrap();
        let workspace = store.add_customer("Dr. Tan", "", "").unwrap();
        let customer_id = workspace.customers[0].id;
        let before = store.load().unwrap();

        let suggestion = store.draft_assistant(customer_id, "en").unwrap();
        assert!(!suggestion.saved);
        assert_eq!(suggestion.provider_trust, "local");
        assert!(suggestion.text.contains("Dr. Tan"));

        // The graph is byte-for-byte unchanged: the suggestion created nothing.
        let after = store.load().unwrap();
        assert_eq!(
            serde_json::to_value(&before).unwrap(),
            serde_json::to_value(&after).unwrap()
        );
        assert!(after.documents.is_empty());

        // Only a disclosure event was recorded.
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
        let ledger_after =
            AuditLedger::load(&_dir.path().join("ledger.json"), device.public_key_b64())
                .unwrap()
                .events()
                .len();
        // Approval added exactly its own events (granted, executed, effect);
        // the two command_center calls added none.
        assert_eq!(ledger_after, ledger_before + 3);
    }
}
