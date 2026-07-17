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
//! Honest labels: documents are template-generated (no model is involved)
//! and the graph schema is a prototype. Approving a send runs the real RFC
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
use sovereign_contracts::{ActionRequest, AutomationLevel, DataClass};
use sovereign_identity::{
    AdmissionRole, ApprovalRole, AuthorityRole, DeviceIdentity, KeyValidity, PublisherRole,
    RoleTrustStore, TypedSigner,
};
use sovereign_policy::{AuthenticatedPolicyContextV2, PolicyEngine};
use sovereign_sandbox::{VerifiedExecutionRequest, VerifiedSandboxExecutor};
use sovereign_vault::Vault;
use uuid::Uuid;

use crate::demo::compile_wat;

pub const WORKSPACE_VAULT_ENTRY: &str = "workspace_graph";
const WORKSPACE_VERSION: u32 = 1;
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Workspace {
    pub version: u32,
    pub venture: Option<Venture>,
    pub customers: Vec<Customer>,
    pub documents: Vec<Document>,
    pub approvals: Vec<Approval>,
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

    pub fn add_customer(&self, name: &str, notes: &str) -> Result<Workspace, WorkspaceError> {
        let name = clean_text("name", name)?;
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
            Some(self.execute_signed_approval(&document)?)
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
        // capability durably consumed, write the approved document to the
        // owner's local outbox. This is audited and revocable; delivery to the
        // customer remains the founder's own action.
        let outbox =
            sovereign_effects::OutboxBroker::open(self.root.join("outbox")).map_err(kernel)?;
        let receipt = outbox
            .write_document(
                &document.id.simple().to_string(),
                sovereign_effects::EffectDataClass::Amber,
                document.body.as_bytes(),
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
            "format": "sovereign-founder-os-export",
            "version": 1,
            "exported_at_unix": now(),
            "device_id": self.device.device_id(),
            "workspace": workspace,
            "audit_chain_verified": chain_ok,
            "audit_events": events,
        }))
    }
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
        let workspace = store.add_customer("Dr. Tan", "met at expo").unwrap();
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
        // file in the local outbox, matching the receipt.
        let outbox_receipt = evidence.outbox.as_ref().unwrap();
        let written = std::fs::read(
            dir.path()
                .join("outbox")
                .join(&outbox_receipt.relative_path),
        )
        .unwrap();
        assert_eq!(written, workspace.documents[0].body.as_bytes());
        assert_eq!(outbox_receipt.bytes, written.len());
    }

    #[test]
    fn double_decision_and_unknown_ids_fail_closed() {
        let (_dir, store) = store();
        store.set_venture("Acme", "Service").unwrap();
        let workspace = store.add_customer("Customer", "").unwrap();
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
}
