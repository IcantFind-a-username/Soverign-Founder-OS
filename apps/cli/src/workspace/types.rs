use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// A durable, owner-visible record of one time a model provider was given
/// customer data. The product's promise is sovereignty over that data, so the
/// founder gets a plain-language log of exactly what happened: which provider,
/// how much it trusts the machine it ran on, whether the data stayed local, and
/// which providers were skipped on the way there. This mirrors the signed
/// `model.drafted` audit event, but keeps the human-readable detail (the event
/// stores only a hash of it) so the log is legible without the export tooling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDisclosure {
    pub id: Uuid,
    pub at: i64,
    pub customer_id: Uuid,
    pub task: String,
    pub provider_id: String,
    pub provider_trust: String,
    /// True when the provider ran locally and the data never left the machine.
    pub stayed_local: bool,
    pub data_class: String,
    pub output_chars: usize,
    /// Providers skipped before this one answered (health-aware failover).
    pub failover_from: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Workspace {
    pub version: u32,
    pub venture: Option<Venture>,
    pub customers: Vec<Customer>,
    pub documents: Vec<Document>,
    pub approvals: Vec<Approval>,
    /// Every time a model provider was shown customer data. Append-only in
    /// practice; `default` keeps vaults written before this field loadable.
    #[serde(default)]
    pub disclosures: Vec<ModelDisclosure>,
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
    pub(super) fn action(kind: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            kind_class: "action".to_owned(),
            count: 0,
            subject: String::new(),
        }
    }
    pub(super) fn with_count(mut self, count: usize) -> Self {
        self.count = count;
        self
    }
    pub(super) fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }
    pub(super) fn risk(kind: &str) -> Self {
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

/// The result of reconciling authoritative state against the signed audit
/// chain. `ok` is the honest bottom line: the chain verifies and every
/// power-granting state has the signed evidence that should back it.
#[derive(Debug, Clone, Serialize)]
pub struct IntegrityReport {
    /// The signed hash chain recomputed and every device signature checked.
    pub chain_verified: bool,
    /// Events on the verified chain.
    pub events: usize,
    /// True when `chain_verified` holds and there are no findings.
    pub ok: bool,
    /// Each divergence between state and the signed chain, never hidden.
    pub findings: Vec<IntegrityFinding>,
}

/// One divergence between authoritative state and the signed audit chain.
#[derive(Debug, Clone, Serialize)]
pub struct IntegrityFinding {
    pub severity: &'static str,
    pub resource: String,
    pub detail: String,
}

/// Short human label for a document status, for honest finding text.
pub(super) fn document_status_label(status: DocumentStatus) -> &'static str {
    match status {
        DocumentStatus::Draft => "a draft",
        DocumentStatus::PendingApproval => "pending approval",
        DocumentStatus::ApprovedPendingDelivery => "approved",
        DocumentStatus::Rejected => "rejected",
        DocumentStatus::Revoked => "revoked",
        DocumentStatus::Delivered => "delivered",
    }
}
