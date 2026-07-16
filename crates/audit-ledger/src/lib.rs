use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sovereign_contracts::{AuditEvent, AuditEventBody};
use sovereign_identity::DeviceIdentity;
use thiserror::Error;
use uuid::Uuid;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("hash chain broken at event {0}")]
    ChainBroken(Uuid),
    #[error("event {0} is missing its device signature")]
    MissingSignature(Uuid),
    #[error("event {0} was not signed by the trusted device")]
    UntrustedDevice(Uuid),
    #[error("ledger is bound to a different device")]
    DeviceMismatch,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("identity error: {0}")]
    Identity(#[from] sovereign_identity::IdentityError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendInput {
    pub venture_id: String,
    pub actor_id: String,
    pub action: String,
    pub resource: String,
    pub capability_id: Option<Uuid>,
    pub payload: serde_json::Value,
    pub policy_decision_hash: Option<String>,
}

/// Append-only audit ledger with hash chain integrity.
#[derive(Debug, Default)]
pub struct AuditLedger {
    events: Vec<AuditEvent>,
    trusted_device_public_key_b64: Option<String>,
}

impl AuditLedger {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            trusted_device_public_key_b64: None,
        }
    }

    pub fn from_events(
        events: Vec<AuditEvent>,
        trusted_device_public_key_b64: impl Into<String>,
    ) -> Result<Self, LedgerError> {
        let ledger = Self {
            events,
            trusted_device_public_key_b64: Some(trusted_device_public_key_b64.into()),
        };
        ledger.verify_chain()?;
        Ok(ledger)
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    pub fn last_hash(&self) -> String {
        self.events
            .last()
            .map(|e| e.event_hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string())
    }

    pub fn append(
        &mut self,
        input: AppendInput,
        device: &DeviceIdentity,
    ) -> Result<AuditEvent, LedgerError> {
        match &self.trusted_device_public_key_b64 {
            Some(key) if key != device.public_key_b64() => {
                return Err(LedgerError::DeviceMismatch);
            }
            Some(_) => {}
            None => {
                self.trusted_device_public_key_b64 = Some(device.public_key_b64().to_owned());
            }
        }

        let payload_bytes = serde_json::to_vec(&input.payload)?;
        let payload_hash = hash_bytes(&payload_bytes);
        let previous_event_hash = self.last_hash();

        let body = AuditEventBody {
            event_id: Uuid::new_v4(),
            venture_id: input.venture_id,
            actor_id: input.actor_id,
            action: input.action,
            resource: input.resource,
            capability_id: input.capability_id,
            timestamp: Utc::now(),
            payload_hash,
            previous_event_hash,
            policy_decision_hash: input.policy_decision_hash,
            device_public_key_b64: device.public_key_b64().to_owned(),
        };

        let event_hash = hash_event_body(&body);
        let sign_message = event_hash.as_bytes();
        let device_signature = Some(device.sign_legacy_v1(sign_message));

        let event = AuditEvent {
            event_id: body.event_id,
            venture_id: body.venture_id,
            actor_id: body.actor_id,
            action: body.action,
            resource: body.resource,
            capability_id: body.capability_id,
            timestamp: body.timestamp,
            payload_hash: body.payload_hash,
            previous_event_hash: body.previous_event_hash,
            policy_decision_hash: body.policy_decision_hash,
            device_public_key_b64: body.device_public_key_b64,
            event_hash,
            device_signature,
        };

        self.events.push(event.clone());
        Ok(event)
    }

    pub fn verify_chain(&self) -> Result<(), LedgerError> {
        let mut expected_prev = GENESIS_HASH.to_string();
        for event in &self.events {
            if self.trusted_device_public_key_b64.as_deref()
                != Some(event.device_public_key_b64.as_str())
            {
                return Err(LedgerError::UntrustedDevice(event.event_id));
            }
            if event.previous_event_hash != expected_prev {
                return Err(LedgerError::ChainBroken(event.event_id));
            }
            let recomputed = hash_event_body(&AuditEventBody::from(event));
            if recomputed != event.event_hash {
                return Err(LedgerError::ChainBroken(event.event_id));
            }
            let signature = event
                .device_signature
                .as_deref()
                .ok_or(LedgerError::MissingSignature(event.event_id))?;
            DeviceIdentity::verify_legacy_v1(
                &event.device_public_key_b64,
                event.event_hash.as_bytes(),
                signature,
            )?;
            expected_prev = event.event_hash.clone();
        }
        Ok(())
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), LedgerError> {
        let json = serde_json::to_vec_pretty(&self.events)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load(
        path: &std::path::Path,
        trusted_device_public_key_b64: impl Into<String>,
    ) -> Result<Self, LedgerError> {
        let bytes = std::fs::read(path)?;
        let events: Vec<AuditEvent> = serde_json::from_slice(&bytes)?;
        Self::from_events(events, trusted_device_public_key_b64)
    }
}

pub fn hash_bytes(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn hash_event_body(body: &AuditEventBody) -> String {
    let json = serde_json::to_vec(body).expect("audit event body must serialize");
    hash_bytes(&json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn append_and_verify_chain() {
        let device = DeviceIdentity::generate();
        let mut ledger = AuditLedger::new();
        ledger
            .append(
                AppendInput {
                    venture_id: "ven_1".into(),
                    actor_id: "agent_researcher".into(),
                    action: "read".into(),
                    resource: "customer:123".into(),
                    capability_id: None,
                    payload: serde_json::json!({"fields": ["display_name"]}),
                    policy_decision_hash: None,
                },
                &device,
            )
            .unwrap();
        ledger.verify_chain().unwrap();
        assert_eq!(ledger.events().len(), 1);
    }

    #[test]
    fn tamper_detection() {
        let device = DeviceIdentity::generate();
        let mut ledger = AuditLedger::new();
        ledger
            .append(
                AppendInput {
                    venture_id: "ven_1".into(),
                    actor_id: "agent".into(),
                    action: "execute".into(),
                    resource: "email:draft".into(),
                    capability_id: None,
                    payload: serde_json::json!({}),
                    policy_decision_hash: None,
                },
                &device,
            )
            .unwrap();
        ledger.events[0].action = "delete".into();
        assert!(ledger.verify_chain().is_err());
    }

    #[test]
    fn persist_ledger() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.json");
        let device = DeviceIdentity::generate();
        let mut ledger = AuditLedger::new();
        ledger
            .append(
                AppendInput {
                    venture_id: "ven_1".into(),
                    actor_id: "agent".into(),
                    action: "plan".into(),
                    resource: "workflow:1".into(),
                    capability_id: None,
                    payload: serde_json::json!({"step": 1}),
                    policy_decision_hash: None,
                },
                &device,
            )
            .unwrap();
        ledger.save(&path).unwrap();
        let loaded = AuditLedger::load(&path, device.public_key_b64()).unwrap();
        assert_eq!(loaded.events().len(), 1);
    }
}
