//! Canonical data contracts for Sovereign Agent Runtime.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Data sensitivity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Red,
    Amber,
    Green,
}

/// Automation level for agent actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AutomationLevel {
    L0Suggest = 0,
    L1Draft = 1,
    L2ApproveExecute = 2,
    L3BoundedAuto = 3,
}

/// A tool or resource action an agent may request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRequest {
    pub actor_id: String,
    pub venture_id: String,
    pub tool: String,
    pub operation: String,
    pub resource: String,
    pub data_class: DataClass,
    pub automation_level: AutomationLevel,
}

/// Deterministic policy decision — never produced by an LLM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision_id: Uuid,
    pub allowed: bool,
    pub reason: String,
    pub requires_approval: bool,
    pub evaluated_at: DateTime<Utc>,
    pub request: ActionRequest,
}

/// Short-lived, scoped execution permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub token_id: Uuid,
    pub venture_id: String,
    pub actor_id: String,
    pub tool: String,
    pub operation: String,
    pub resource: String,
    pub max_uses: u32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub policy_decision_id: Uuid,
    pub issuer_public_key_b64: String,
    pub signature_b64: String,
}

/// Canonical signed content of a capability token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityTokenBody {
    pub token_id: Uuid,
    pub venture_id: String,
    pub actor_id: String,
    pub tool: String,
    pub operation: String,
    pub resource: String,
    pub max_uses: u32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub policy_decision_id: Uuid,
    pub issuer_public_key_b64: String,
}

impl From<&CapabilityToken> for CapabilityTokenBody {
    fn from(token: &CapabilityToken) -> Self {
        Self {
            token_id: token.token_id,
            venture_id: token.venture_id.clone(),
            actor_id: token.actor_id.clone(),
            tool: token.tool.clone(),
            operation: token.operation.clone(),
            resource: token.resource.clone(),
            max_uses: token.max_uses,
            issued_at: token.issued_at,
            expires_at: token.expires_at,
            policy_decision_id: token.policy_decision_id,
            issuer_public_key_b64: token.issuer_public_key_b64.clone(),
        }
    }
}

/// Append-only signed audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: Uuid,
    pub venture_id: String,
    pub actor_id: String,
    pub action: String,
    pub resource: String,
    pub capability_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub payload_hash: String,
    pub previous_event_hash: String,
    pub policy_decision_hash: Option<String>,
    pub device_public_key_b64: String,
    pub event_hash: String,
    pub device_signature: Option<String>,
}

/// Canonical hash input for an audit event (excludes event_hash and signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventBody {
    pub event_id: Uuid,
    pub venture_id: String,
    pub actor_id: String,
    pub action: String,
    pub resource: String,
    pub capability_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub payload_hash: String,
    pub previous_event_hash: String,
    pub policy_decision_hash: Option<String>,
    pub device_public_key_b64: String,
}

impl From<&AuditEvent> for AuditEventBody {
    fn from(event: &AuditEvent) -> Self {
        Self {
            event_id: event.event_id,
            venture_id: event.venture_id.clone(),
            actor_id: event.actor_id.clone(),
            action: event.action.clone(),
            resource: event.resource.clone(),
            capability_id: event.capability_id,
            timestamp: event.timestamp,
            payload_hash: event.payload_hash.clone(),
            previous_event_hash: event.previous_event_hash.clone(),
            policy_decision_hash: event.policy_decision_hash.clone(),
            device_public_key_b64: event.device_public_key_b64.clone(),
        }
    }
}
