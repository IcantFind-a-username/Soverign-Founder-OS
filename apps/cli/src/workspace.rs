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
//!   executed: they enter a pending-approval queue for the human owner, and
//!   even an approval only records the decision — Stage 1 has no external
//!   effects, so delivery is explicitly deferred, never simulated;
//! - the founder can export every byte of their business state at any time.
//!
//! Honest labels: documents are template-generated (no model is involved),
//! the graph schema is a prototype and may change, and approval records here
//! are workflow evidence in the audit ledger — not yet the signed
//! `ApprovalEvidenceV2` protocol required before effectful execution.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sovereign_audit_ledger::{hash_bytes, AppendInput, AuditLedger};
use sovereign_contracts::{ActionRequest, AutomationLevel, DataClass};
use sovereign_identity::DeviceIdentity;
use sovereign_policy::PolicyEngine;
use sovereign_vault::Vault;
use uuid::Uuid;

pub const WORKSPACE_VAULT_ENTRY: &str = "workspace_graph";
const WORKSPACE_VERSION: u32 = 1;
const MAX_TEXT_FIELD_BYTES: usize = 4 * 1024;
const MAX_CUSTOMERS: usize = 500;
const MAX_DOCUMENTS: usize = 2_000;

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
        };
        let resource = format!("document:{document_id}");
        let summary = serde_json::json!({ "approval_id": approval.id });
        workspace.approvals.push(approval);
        self.save(&workspace)?;
        self.record("approval.requested", &resource, summary)?;
        Ok(workspace)
    }

    /// The human owner decides. Stage 1 has no external effects, so an
    /// approval marks the document approved-pending-delivery; it does not and
    /// cannot send anything.
    pub fn decide(&self, approval_id: Uuid, approve: bool) -> Result<Workspace, WorkspaceError> {
        let mut workspace = self.load()?;
        let approval = workspace
            .approvals
            .iter_mut()
            .find(|approval| approval.id == approval_id)
            .ok_or_else(|| WorkspaceError::NotFound("approval".into()))?;
        if approval.status != ApprovalStatus::Pending {
            return Err(WorkspaceError::Invalid("approval already decided".into()));
        }
        approval.status = if approve {
            ApprovalStatus::Approved
        } else {
            ApprovalStatus::Rejected
        };
        approval.decided_at = Some(now());
        let document_id = approval.document_id;
        let action = if approve {
            "approval.granted"
        } else {
            "approval.rejected"
        };
        let summary = serde_json::json!({ "approval_id": approval_id, "approved": approve });

        let document = workspace
            .documents
            .iter_mut()
            .find(|document| document.id == document_id)
            .ok_or_else(|| WorkspaceError::NotFound("document".into()))?;
        document.status = if approve {
            DocumentStatus::ApprovedPendingDelivery
        } else {
            DocumentStatus::Rejected
        };

        self.save(&workspace)?;
        self.record(action, &format!("document:{document_id}"), summary)?;
        Ok(workspace)
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
            ]
        );
        ledger.verify_chain().unwrap();
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
