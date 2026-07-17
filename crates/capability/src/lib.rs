//! Capability authorization protocols.
//!
//! The original `CapabilityToken` API is retained as explicit V1 compatibility
//! for the Phase A, pure-compute path. New code must use [`v2`] when binding an
//! exact prepared invocation.

pub mod approval;
pub mod v2;

use chrono::{DateTime, Duration, Utc};
use sovereign_contracts::{CapabilityToken, CapabilityTokenBody, PolicyDecision};
use sovereign_identity::DeviceIdentity;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("policy denied the request")]
    PolicyDenied,
    #[error("human approval required before issuing token")]
    ApprovalRequired,
    #[error("token expired")]
    Expired,
    #[error("token exhausted")]
    Exhausted,
    #[error("token scope mismatch")]
    ScopeMismatch,
    #[error("venture mismatch")]
    VentureMismatch,
    #[error("actor mismatch")]
    ActorMismatch,
    #[error("token was not signed by the trusted issuer")]
    UntrustedIssuer,
    #[error("token signature is invalid")]
    InvalidSignature,
    #[error("token lifetime must be positive")]
    InvalidLifetime,
    #[error("token use limit must be positive")]
    InvalidUseLimit,
}

#[derive(Debug, Clone)]
pub struct IssueOptions {
    pub ttl: Duration,
    pub max_uses: u32,
}

impl Default for IssueOptions {
    fn default() -> Self {
        Self {
            ttl: Duration::minutes(5),
            max_uses: 1,
        }
    }
}

#[derive(Debug)]
pub struct CapabilityIssuer {
    identity: DeviceIdentity,
}

/// Explicit name for the legacy Phase A issuer.
pub type CapabilityIssuerV1 = CapabilityIssuer;

impl CapabilityIssuer {
    pub fn new() -> Self {
        Self {
            identity: DeviceIdentity::generate(),
        }
    }

    pub fn public_key_b64(&self) -> &str {
        self.identity.public_key_b64()
    }

    pub fn issue(
        &self,
        decision: &PolicyDecision,
        options: IssueOptions,
        approved: bool,
    ) -> Result<CapabilityToken, CapabilityError> {
        if !decision.allowed {
            return Err(CapabilityError::PolicyDenied);
        }
        if decision.requires_approval && !approved {
            return Err(CapabilityError::ApprovalRequired);
        }
        if options.ttl <= Duration::zero() {
            return Err(CapabilityError::InvalidLifetime);
        }
        if options.max_uses == 0 {
            return Err(CapabilityError::InvalidUseLimit);
        }

        let now = Utc::now();
        let mut token = CapabilityToken {
            token_id: Uuid::new_v4(),
            venture_id: decision.request.venture_id.clone(),
            actor_id: decision.request.actor_id.clone(),
            tool: decision.request.tool.clone(),
            operation: decision.request.operation.clone(),
            resource: decision.request.resource.clone(),
            max_uses: options.max_uses,
            issued_at: now,
            expires_at: now + options.ttl,
            policy_decision_id: decision.decision_id,
            issuer_public_key_b64: self.identity.public_key_b64().to_owned(),
            signature_b64: String::new(),
        };
        token.signature_b64 = self.identity.sign_legacy_v1(&token_signing_bytes(&token));
        Ok(token)
    }
}

impl Default for CapabilityIssuer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct CapabilityValidator {
    trusted_issuer_public_key_b64: String,
    uses: std::collections::HashMap<Uuid, u32>,
}

/// Explicit name for the process-local legacy Phase A validator.
pub type CapabilityValidatorV1 = CapabilityValidator;

#[derive(Debug, Clone, Copy)]
pub struct ValidationContext<'a> {
    pub venture_id: &'a str,
    pub actor_id: &'a str,
    pub tool: &'a str,
    pub operation: &'a str,
    pub resource: &'a str,
    pub now: DateTime<Utc>,
}

impl CapabilityValidator {
    pub fn new(trusted_issuer_public_key_b64: impl Into<String>) -> Self {
        Self {
            trusted_issuer_public_key_b64: trusted_issuer_public_key_b64.into(),
            uses: std::collections::HashMap::new(),
        }
    }

    pub fn validate(
        &mut self,
        token: &CapabilityToken,
        context: ValidationContext<'_>,
    ) -> Result<(), CapabilityError> {
        if token.issuer_public_key_b64 != self.trusted_issuer_public_key_b64 {
            return Err(CapabilityError::UntrustedIssuer);
        }
        DeviceIdentity::verify_legacy_v1(
            &token.issuer_public_key_b64,
            &token_signing_bytes(token),
            &token.signature_b64,
        )
        .map_err(|_| CapabilityError::InvalidSignature)?;
        if token.venture_id != context.venture_id {
            return Err(CapabilityError::VentureMismatch);
        }
        if token.actor_id != context.actor_id {
            return Err(CapabilityError::ActorMismatch);
        }
        if token.tool != context.tool
            || token.operation != context.operation
            || token.resource != context.resource
        {
            return Err(CapabilityError::ScopeMismatch);
        }
        if context.now >= token.expires_at {
            return Err(CapabilityError::Expired);
        }

        let count = self.uses.entry(token.token_id).or_insert(0);
        if *count >= token.max_uses {
            return Err(CapabilityError::Exhausted);
        }
        *count += 1;
        Ok(())
    }
}

fn token_signing_bytes(token: &CapabilityToken) -> Vec<u8> {
    serde_json::to_vec(&CapabilityTokenBody::from(token))
        .expect("capability token body must serialize")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sovereign_contracts::{ActionRequest, AutomationLevel, DataClass};
    use sovereign_policy::PolicyEngine;

    #[test]
    fn issue_and_consume_token() {
        let engine = PolicyEngine::new();
        let request = ActionRequest {
            actor_id: "agent".into(),
            venture_id: "ven_1".into(),
            tool: "email".into(),
            operation: "draft".into(),
            resource: "customer:1".into(),
            data_class: DataClass::Amber,
            automation_level: AutomationLevel::L1Draft,
        };
        let decision = engine.evaluate(request);
        let issuer = CapabilityIssuer::new();
        let token = issuer
            .issue(&decision, IssueOptions::default(), false)
            .unwrap();

        let mut validator = CapabilityValidator::new(issuer.public_key_b64());
        validator
            .validate(&token, validation_context("draft"))
            .unwrap();
        assert_eq!(
            validator.validate(&token, validation_context("draft")),
            Err(CapabilityError::Exhausted)
        );
    }

    #[test]
    fn rejects_scope_mismatch() {
        let engine = PolicyEngine::new();
        let request = ActionRequest {
            actor_id: "agent".into(),
            venture_id: "ven_1".into(),
            tool: "email".into(),
            operation: "draft".into(),
            resource: "customer:1".into(),
            data_class: DataClass::Green,
            automation_level: AutomationLevel::L1Draft,
        };
        let decision = engine.evaluate(request);
        let issuer = CapabilityIssuer::new();
        let token = issuer
            .issue(&decision, IssueOptions::default(), false)
            .unwrap();
        let mut validator = CapabilityValidator::new(issuer.public_key_b64());
        assert_eq!(
            validator.validate(
                &token,
                ValidationContext {
                    operation: "send",
                    ..validation_context("draft")
                },
            ),
            Err(CapabilityError::ScopeMismatch)
        );
    }

    fn validation_context(operation: &str) -> ValidationContext<'_> {
        ValidationContext {
            venture_id: "ven_1",
            actor_id: "agent",
            tool: "email",
            operation,
            resource: "customer:1",
            now: Utc::now(),
        }
    }
}
