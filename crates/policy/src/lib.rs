use std::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sovereign_artifact::{
    ArtifactBackend, Digest, PreparedInvocation, RiskClass, CANONICALIZATION_PROFILE,
};
use sovereign_contracts::{ActionRequest, AutomationLevel, DataClass, PolicyDecision};
use thiserror::Error;
use uuid::Uuid;

/// High-risk operations are structured pairs. Dotted aliases and tool-level
/// wildcards are deliberately not accepted at the policy boundary.
const HIGH_RISK_OPERATIONS: &[(&str, &str)] = &[
    ("email", "send"),
    ("payment", "transfer"),
    ("contract", "sign"),
    ("deploy", "production"),
    ("file", "delete"),
    ("social", "publish"),
];

/// Operations blocked for cloud-bound data classes.
const CLOUD_BLOCKED_CLASSES: &[DataClass] = &[DataClass::Red];
const POLICY_AUTHORIZATION_V2_TYPE: &str = "sovereign.policy-authorization";
const POLICY_AUTHORIZATION_V2_VERSION: u16 = 2;

pub trait TrustedClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl TrustedClock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyV2Error {
    #[error("invalid authenticated policy context: {0}")]
    InvalidContext(&'static str),
    #[error("the prepared invocation has no primary resource binding")]
    MissingPrimaryResource,
}

/// Host-authenticated context used to ask policy about one prepared
/// invocation. Construction validates shape only; the trusted host remains
/// responsible for authenticating these values before creating the context.
#[derive(Debug)]
pub struct AuthenticatedPolicyContextV2 {
    audience: String,
    venture_id: String,
    subject_id: String,
    session_id: Uuid,
    data_class: DataClass,
    automation_level: AutomationLevel,
    idempotency_key: Uuid,
}

impl AuthenticatedPolicyContextV2 {
    pub fn new(
        audience: impl Into<String>,
        venture_id: impl Into<String>,
        subject_id: impl Into<String>,
        session_id: Uuid,
        data_class: DataClass,
        automation_level: AutomationLevel,
        idempotency_key: Uuid,
    ) -> Result<Self, PolicyV2Error> {
        let audience = audience.into();
        let venture_id = venture_id.into();
        let subject_id = subject_id.into();
        validate_context_identifier(&audience, "audience")?;
        validate_context_identifier(&venture_id, "venture_id")?;
        validate_context_identifier(&subject_id, "subject_id")?;
        if session_id.is_nil() {
            return Err(PolicyV2Error::InvalidContext("session_id"));
        }
        if idempotency_key.is_nil() {
            return Err(PolicyV2Error::InvalidContext("idempotency_key"));
        }
        Ok(Self {
            audience,
            venture_id,
            subject_id,
            session_id,
            data_class,
            automation_level,
            idempotency_key,
        })
    }
}

#[derive(Serialize)]
struct PolicyToolBindingV2 {
    tool_id: String,
    tool_version: String,
    operation: String,
}

#[derive(Serialize)]
struct PolicyAuthorizationBodyV2 {
    typ: &'static str,
    version: u16,
    decision_id: Uuid,
    allowed: bool,
    reason: String,
    requires_approval: bool,
    evaluated_at_unix: i64,
    audience: String,
    venture_id: String,
    subject_id: String,
    session_id: Uuid,
    data_class: DataClass,
    automation_level: AutomationLevel,
    idempotency_key: Uuid,
    tool: PolicyToolBindingV2,
    component_digest: Digest,
    manifest_digest: Digest,
    canonical_input_digest: Digest,
    resource_bindings_digest: Digest,
    canonicalization_profile: &'static str,
    primary_resource: String,
    risk_class: RiskClass,
    backend: ArtifactBackend,
}

/// Opaque policy proof for one exact prepared invocation.
///
/// It intentionally implements `Serialize` but not `Deserialize`, has no
/// public fields, and has no public constructor. Only
/// [`PolicyEngine::evaluate_prepared`] can create one.
#[derive(Serialize)]
#[serde(transparent)]
pub struct PolicyAuthorizationV2 {
    body: PolicyAuthorizationBodyV2,
}

impl fmt::Debug for PolicyAuthorizationV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyAuthorizationV2")
            .field("decision_id", &self.body.decision_id)
            .field("allowed", &self.body.allowed)
            .field("requires_approval", &self.body.requires_approval)
            .field("evaluated_at_unix", &self.body.evaluated_at_unix)
            .finish_non_exhaustive()
    }
}

impl PolicyAuthorizationV2 {
    pub fn decision_id(&self) -> Uuid {
        self.body.decision_id
    }

    pub fn allowed(&self) -> bool {
        self.body.allowed
    }

    pub fn requires_approval(&self) -> bool {
        self.body.requires_approval
    }

    pub fn evaluated_at_unix(&self) -> i64 {
        self.body.evaluated_at_unix
    }

    pub fn audience(&self) -> &str {
        &self.body.audience
    }

    pub fn venture_id(&self) -> &str {
        &self.body.venture_id
    }

    pub fn subject_id(&self) -> &str {
        &self.body.subject_id
    }

    pub fn session_id(&self) -> Uuid {
        self.body.session_id
    }

    pub fn idempotency_key(&self) -> Uuid {
        self.body.idempotency_key
    }

    pub fn tool_id(&self) -> &str {
        &self.body.tool.tool_id
    }

    pub fn tool_version(&self) -> &str {
        &self.body.tool.tool_version
    }

    pub fn operation(&self) -> &str {
        &self.body.tool.operation
    }

    pub fn component_digest(&self) -> Digest {
        self.body.component_digest
    }

    pub fn manifest_digest(&self) -> Digest {
        self.body.manifest_digest
    }

    pub fn canonical_input_digest(&self) -> Digest {
        self.body.canonical_input_digest
    }

    pub fn resource_bindings_digest(&self) -> Digest {
        self.body.resource_bindings_digest
    }

    pub fn canonicalization_profile(&self) -> &str {
        self.body.canonicalization_profile
    }

    pub fn primary_resource(&self) -> &str {
        &self.body.primary_resource
    }

    pub fn risk_class(&self) -> RiskClass {
        self.body.risk_class
    }

    pub fn backend(&self) -> ArtifactBackend {
        self.body.backend
    }
}

/// Deterministic policy engine. LLM output never bypasses this layer.
#[derive(Debug)]
pub struct PolicyEngine<C = SystemClock> {
    clock: C,
}

impl PolicyEngine<SystemClock> {
    pub fn new() -> Self {
        Self { clock: SystemClock }
    }
}

impl Default for PolicyEngine<SystemClock> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: TrustedClock> PolicyEngine<C> {
    pub fn with_clock(clock: C) -> Self {
        Self { clock }
    }

    /// Legacy V1 policy decision. Capability V2 deliberately does not accept
    /// this forgeable data contract.
    pub fn evaluate(&self, request: ActionRequest) -> PolicyDecision {
        let outcome = evaluate_rules(
            &request.tool,
            &request.operation,
            &request.resource,
            request.data_class,
            request.automation_level,
        );
        PolicyDecision {
            decision_id: Uuid::new_v4(),
            allowed: outcome.allowed,
            reason: outcome.reason,
            requires_approval: outcome.requires_approval,
            evaluated_at: self.clock.now(),
            request,
        }
    }

    /// Evaluate one concrete artifact-prepared invocation and return an opaque
    /// authorization whose serialized body binds every security-relevant input.
    pub fn evaluate_prepared(
        &self,
        prepared: &PreparedInvocation,
        context: AuthenticatedPolicyContextV2,
    ) -> Result<PolicyAuthorizationV2, PolicyV2Error> {
        let primary_resource = prepared
            .primary_resource()
            .ok_or(PolicyV2Error::MissingPrimaryResource)?;
        let operation = prepared.operation();
        let outcome = evaluate_rules(
            operation.tool_id(),
            operation.operation_id(),
            primary_resource,
            context.data_class,
            context.automation_level,
        );

        Ok(PolicyAuthorizationV2 {
            body: PolicyAuthorizationBodyV2 {
                typ: POLICY_AUTHORIZATION_V2_TYPE,
                version: POLICY_AUTHORIZATION_V2_VERSION,
                decision_id: Uuid::new_v4(),
                allowed: outcome.allowed,
                reason: outcome.reason,
                requires_approval: outcome.requires_approval,
                evaluated_at_unix: self.clock.now().timestamp(),
                audience: context.audience,
                venture_id: context.venture_id,
                subject_id: context.subject_id,
                session_id: context.session_id,
                data_class: context.data_class,
                automation_level: context.automation_level,
                idempotency_key: context.idempotency_key,
                tool: PolicyToolBindingV2 {
                    tool_id: operation.tool_id().to_owned(),
                    tool_version: operation.tool_version().to_owned(),
                    operation: operation.operation_id().to_owned(),
                },
                component_digest: prepared.artifact().component_digest(),
                manifest_digest: prepared.artifact().manifest_digest(),
                canonical_input_digest: prepared.input_digest(),
                resource_bindings_digest: prepared.bindings_digest(),
                canonicalization_profile: CANONICALIZATION_PROFILE,
                primary_resource: primary_resource.to_owned(),
                risk_class: prepared.artifact().manifest().risk_class(),
                backend: prepared.artifact().manifest().backend(),
            },
        })
    }
}

struct PolicyOutcome {
    allowed: bool,
    requires_approval: bool,
    reason: String,
}

fn evaluate_rules(
    tool_id: &str,
    operation_id: &str,
    resource: &str,
    data_class: DataClass,
    automation_level: AutomationLevel,
) -> PolicyOutcome {
    let mut denial_reasons = Vec::new();
    let mut approval_reasons = Vec::new();

    if CLOUD_BLOCKED_CLASSES.contains(&data_class) && tool_id.starts_with("cloud.") {
        denial_reasons.push("red-zone data cannot be sent to cloud tools");
    }

    if automation_level >= AutomationLevel::L2ApproveExecute {
        approval_reasons.push("L2+ actions require human approval");
    }

    if HIGH_RISK_OPERATIONS
        .iter()
        .any(|(tool, operation)| *tool == tool_id && *operation == operation_id)
    {
        approval_reasons.push("high-risk operation requires explicit approval");
    }

    if resource.contains("..") || resource.starts_with('/') {
        denial_reasons.push("path traversal or absolute path access denied");
    }

    let allowed = denial_reasons.is_empty();
    let requires_approval = !approval_reasons.is_empty();
    let reasons = denial_reasons
        .into_iter()
        .chain(approval_reasons)
        .collect::<Vec<_>>();
    let reason = if reasons.is_empty() {
        "allowed by default policy".to_owned()
    } else {
        reasons.join("; ")
    };
    PolicyOutcome {
        allowed,
        requires_approval,
        reason,
    }
}

fn validate_context_identifier(value: &str, field: &'static str) -> Result<(), PolicyV2Error> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > 512
        || value.chars().any(char::is_control)
    {
        return Err(PolicyV2Error::InvalidContext(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(tool: &str, op: &str, class: DataClass, level: AutomationLevel) -> ActionRequest {
        ActionRequest {
            actor_id: "agent_1".into(),
            venture_id: "ven_1".into(),
            tool: tool.into(),
            operation: op.into(),
            resource: "customer:123".into(),
            data_class: class,
            automation_level: level,
        }
    }

    #[test]
    fn blocks_red_data_to_cloud() {
        let engine = PolicyEngine::new();
        let decision = engine.evaluate(req(
            "cloud.model",
            "infer",
            DataClass::Red,
            AutomationLevel::L1Draft,
        ));
        assert!(!decision.allowed);
    }

    #[test]
    fn high_risk_requires_exact_structured_operation() {
        let engine = PolicyEngine::new();
        let decision = engine.evaluate(req(
            "email",
            "send",
            DataClass::Green,
            AutomationLevel::L1Draft,
        ));
        assert!(decision.requires_approval);

        let dotted_alias = engine.evaluate(req(
            "email.send",
            "unrelated",
            DataClass::Green,
            AutomationLevel::L1Draft,
        ));
        assert!(!dotted_alias.requires_approval);
    }

    #[test]
    fn blocks_path_traversal() {
        let engine = PolicyEngine::new();
        let mut request = req("file", "read", DataClass::Green, AutomationLevel::L1Draft);
        request.resource = "../secrets".into();
        let decision = engine.evaluate(request);
        assert!(!decision.allowed);
    }
}
