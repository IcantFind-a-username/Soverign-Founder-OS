//! RFC 0003: signed human approval evidence.
//!
//! An approval is a COSE_Sign1 object signed under the dedicated approval
//! role, binding one exact prepared invocation and one exact policy decision.
//! It is verified both at capability issuance and again at consumption, so
//! both sides observe the same evidence bytes. One-use accounting is
//! process-local in this stage, like every other replay defense on this
//! branch, and approvals authorize pure computation only.

use std::fmt;

use serde::{Deserialize, Serialize};
use sovereign_artifact::{Digest, PreparedInvocation, CANONICALIZATION_PROFILE};
use sovereign_identity::{ApprovalRole, RoleTrustStore, TypedSigner};
use sovereign_policy::PolicyAuthorizationV2;
use uuid::Uuid;

use crate::v2::{policy_decision_digest, CapabilityV2Error, ToolScopeV2, TrustedClock};

pub const APPROVAL_TYPE: &str = "sovereign.approval";
pub const APPROVAL_VERSION: u16 = 1;
pub const APPROVAL_MAX_TTL_SECONDS: i64 = 10 * 60;
pub const APPROVAL_MAX_SIGNED_BYTES: usize = 32 * 1024;
const APPROVAL_MAX_PAYLOAD_BYTES: usize = 16 * 1024;

/// Strict canonical payload of a signed approval. Public fields support
/// inspection after verification; execution paths never accept the claims
/// directly, only the opaque signed object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalClaimsV1 {
    pub typ: String,
    pub version: u16,
    pub approval_id: Uuid,
    pub approver_issuer: String,
    pub approver_key_id: Digest,
    pub approver_subject_id: String,
    pub audience: String,
    pub venture_id: String,
    pub subject_id: String,
    pub session_id: Uuid,
    pub tool: ToolScopeV2,
    pub component_digest: Digest,
    pub manifest_digest: Digest,
    pub canonical_input_digest: Digest,
    pub resource_bindings_digest: Digest,
    pub primary_resource: String,
    pub policy_decision_id: Uuid,
    pub policy_decision_digest: Digest,
    pub canonicalization_profile: String,
    pub approved_at_unix: i64,
    pub expires_at_unix: i64,
}

/// Opaque signed approval bytes. Construction grants no trust; only
/// verification against a role-specific trust store opens it.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedApprovalV1 {
    cose_sign1: Vec<u8>,
}

impl SignedApprovalV1 {
    pub fn from_cose_sign1(cose_sign1: Vec<u8>) -> Self {
        Self { cose_sign1 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.cose_sign1
    }
}

impl fmt::Debug for SignedApprovalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedApprovalV1")
            .field("cose_sign1_bytes", &self.cose_sign1.len())
            .finish_non_exhaustive()
    }
}

/// Everything the human owner's device needs to sign an approval for one
/// exact prepared invocation under one exact policy decision.
pub struct ApprovalGrantRequest<'a> {
    pub approver_subject_id: &'a str,
    pub audience: &'a str,
    pub venture_id: &'a str,
    pub subject_id: &'a str,
    pub session_id: Uuid,
    pub policy_decision: &'a PolicyAuthorizationV2,
    pub prepared_invocation: &'a PreparedInvocation,
    pub ttl_seconds: i64,
}

/// Sign approval evidence. This runs on the owner's device with the owner's
/// approval key; nothing about it grants execution by itself.
pub fn approve_invocation<C: TrustedClock>(
    signer: &TypedSigner<ApprovalRole>,
    clock: &C,
    request: ApprovalGrantRequest<'_>,
) -> Result<SignedApprovalV1, CapabilityV2Error> {
    if request.ttl_seconds <= 0 || request.ttl_seconds > APPROVAL_MAX_TTL_SECONDS {
        return Err(CapabilityV2Error::ApprovalLifetimeInvalid);
    }
    if request.approver_subject_id.is_empty()
        || request.approver_subject_id.trim() != request.approver_subject_id
        || request.approver_subject_id.len() > 512
    {
        return Err(CapabilityV2Error::InvalidApprovalClaims);
    }
    let approved_at_unix = clock.now_unix();
    let prepared = request.prepared_invocation;
    let operation = prepared.operation();
    let primary_resource = prepared
        .primary_resource()
        .ok_or(CapabilityV2Error::MissingPrimaryResource)?;

    let claims = ApprovalClaimsV1 {
        typ: APPROVAL_TYPE.to_owned(),
        version: APPROVAL_VERSION,
        approval_id: Uuid::new_v4(),
        approver_issuer: signer.issuer().to_owned(),
        approver_key_id: Digest::from_bytes(*signer.key_id()),
        approver_subject_id: request.approver_subject_id.to_owned(),
        audience: request.audience.to_owned(),
        venture_id: request.venture_id.to_owned(),
        subject_id: request.subject_id.to_owned(),
        session_id: request.session_id,
        tool: ToolScopeV2 {
            tool_id: operation.tool_id().to_owned(),
            tool_version: operation.tool_version().to_owned(),
            operation: operation.operation_id().to_owned(),
        },
        component_digest: prepared.artifact().component_digest(),
        manifest_digest: prepared.artifact().manifest_digest(),
        canonical_input_digest: prepared.input_digest(),
        resource_bindings_digest: prepared.bindings_digest(),
        primary_resource: primary_resource.to_owned(),
        policy_decision_id: request.policy_decision.decision_id(),
        policy_decision_digest: policy_decision_digest(request.policy_decision)?,
        canonicalization_profile: CANONICALIZATION_PROFILE.to_owned(),
        approved_at_unix,
        expires_at_unix: approved_at_unix
            .checked_add(request.ttl_seconds)
            .ok_or(CapabilityV2Error::ApprovalLifetimeInvalid)?,
    };
    let canonical = serde_json_canonicalizer::to_vec(&claims)
        .map_err(|_| CapabilityV2Error::CanonicalizationFailed)?;
    if canonical.len() > APPROVAL_MAX_PAYLOAD_BYTES {
        return Err(CapabilityV2Error::InvalidApprovalClaims);
    }
    let cose_sign1 = signer
        .sign_cose(&canonical)
        .map_err(|_| CapabilityV2Error::SigningFailed)?;
    if cose_sign1.len() > APPROVAL_MAX_SIGNED_BYTES {
        return Err(CapabilityV2Error::InvalidApprovalClaims);
    }
    Ok(SignedApprovalV1 { cose_sign1 })
}

/// The exact context a signed approval must bind to be accepted.
pub(crate) struct ApprovalVerificationContext<'a> {
    pub trust: &'a RoleTrustStore<ApprovalRole>,
    pub expected_issuer: &'a str,
    pub audience: &'a str,
    pub venture_id: &'a str,
    pub subject_id: &'a str,
    pub session_id: Uuid,
    pub policy_decision: &'a PolicyAuthorizationV2,
    pub prepared: &'a PreparedInvocation,
    pub now_unix: i64,
}

/// Fail-closed verification of a signed approval against the exact prepared
/// invocation and policy decision it must approve.
pub(crate) fn verify_approval(
    approval: &SignedApprovalV1,
    context: ApprovalVerificationContext<'_>,
) -> Result<ApprovalClaimsV1, CapabilityV2Error> {
    let ApprovalVerificationContext {
        trust,
        expected_issuer,
        audience,
        venture_id,
        subject_id,
        session_id,
        policy_decision,
        prepared,
        now_unix,
    } = context;
    if approval.as_bytes().len() > APPROVAL_MAX_SIGNED_BYTES {
        return Err(CapabilityV2Error::InvalidApprovalClaims);
    }
    let verified = trust
        .verify(approval.as_bytes(), expected_issuer, now_unix)
        .map_err(map_approval_identity_error)?;
    if verified.payload().len() > APPROVAL_MAX_PAYLOAD_BYTES {
        return Err(CapabilityV2Error::InvalidApprovalClaims);
    }
    let claims: ApprovalClaimsV1 = serde_json::from_slice(verified.payload())
        .map_err(|_| CapabilityV2Error::InvalidApprovalClaims)?;
    let canonical = serde_json_canonicalizer::to_vec(&claims)
        .map_err(|_| CapabilityV2Error::CanonicalizationFailed)?;
    if canonical != verified.payload() {
        return Err(CapabilityV2Error::NonCanonicalApproval);
    }

    if claims.typ != APPROVAL_TYPE {
        return Err(CapabilityV2Error::ApprovalMismatch("typ"));
    }
    if claims.version != APPROVAL_VERSION {
        return Err(CapabilityV2Error::ApprovalMismatch("version"));
    }
    if claims.approver_issuer != verified.issuer() {
        return Err(CapabilityV2Error::ApprovalMismatch("approver_issuer"));
    }
    if claims.approver_key_id.as_bytes() != verified.key_id() {
        return Err(CapabilityV2Error::ApprovalMismatch("approver_key_id"));
    }
    if claims.approver_subject_id.is_empty() {
        return Err(CapabilityV2Error::InvalidApprovalClaims);
    }
    if claims.audience != audience {
        return Err(CapabilityV2Error::ApprovalMismatch("audience"));
    }
    if claims.venture_id != venture_id {
        return Err(CapabilityV2Error::ApprovalMismatch("venture_id"));
    }
    if claims.subject_id != subject_id {
        return Err(CapabilityV2Error::ApprovalMismatch("subject_id"));
    }
    if claims.session_id != session_id {
        return Err(CapabilityV2Error::ApprovalMismatch("session_id"));
    }
    if claims.canonicalization_profile != CANONICALIZATION_PROFILE {
        return Err(CapabilityV2Error::ApprovalMismatch(
            "canonicalization_profile",
        ));
    }

    let operation = prepared.operation();
    if claims.tool.tool_id != operation.tool_id()
        || claims.tool.tool_version != operation.tool_version()
        || claims.tool.operation != operation.operation_id()
    {
        return Err(CapabilityV2Error::ApprovalMismatch("tool"));
    }
    let primary_resource = prepared
        .primary_resource()
        .ok_or(CapabilityV2Error::MissingPrimaryResource)?;
    if claims.primary_resource != primary_resource {
        return Err(CapabilityV2Error::ApprovalMismatch("primary_resource"));
    }
    let digest_checks = [
        (
            "component_digest",
            claims.component_digest,
            prepared.artifact().component_digest(),
        ),
        (
            "manifest_digest",
            claims.manifest_digest,
            prepared.artifact().manifest_digest(),
        ),
        (
            "canonical_input_digest",
            claims.canonical_input_digest,
            prepared.input_digest(),
        ),
        (
            "resource_bindings_digest",
            claims.resource_bindings_digest,
            prepared.bindings_digest(),
        ),
    ];
    for (field, claimed, actual) in digest_checks {
        if claimed != actual {
            return Err(CapabilityV2Error::ApprovalMismatch(field));
        }
    }
    if claims.policy_decision_id != policy_decision.decision_id()
        || claims.policy_decision_digest != policy_decision_digest(policy_decision)?
    {
        return Err(CapabilityV2Error::ApprovalMismatch("policy_decision"));
    }

    let lifetime = claims
        .expires_at_unix
        .checked_sub(claims.approved_at_unix)
        .ok_or(CapabilityV2Error::ApprovalLifetimeInvalid)?;
    if lifetime <= 0 || lifetime > APPROVAL_MAX_TTL_SECONDS {
        return Err(CapabilityV2Error::ApprovalLifetimeInvalid);
    }
    if claims.approved_at_unix > now_unix {
        return Err(CapabilityV2Error::ApprovalFromFuture);
    }
    if now_unix >= claims.expires_at_unix {
        return Err(CapabilityV2Error::ApprovalExpired);
    }
    // The human must have approved this decision after it was evaluated.
    if claims.approved_at_unix < policy_decision.evaluated_at_unix() {
        return Err(CapabilityV2Error::ApprovalMismatch("approved_at_unix"));
    }
    Ok(claims)
}

fn map_approval_identity_error(error: sovereign_identity::IdentityError) -> CapabilityV2Error {
    use sovereign_identity::IdentityError;
    match error {
        IdentityError::UnknownKeyId => CapabilityV2Error::UnknownApprovalKey,
        IdentityError::IssuerMismatch | IdentityError::InvalidIssuer => {
            CapabilityV2Error::ApprovalIssuerMismatch
        }
        IdentityError::KeyRevoked => CapabilityV2Error::ApprovalKeyRevoked,
        IdentityError::KeyNotYetValid => CapabilityV2Error::ApprovalKeyNotYetValid,
        IdentityError::KeyExpired => CapabilityV2Error::ApprovalKeyExpired,
        IdentityError::VerificationFailed => CapabilityV2Error::InvalidApprovalSignature,
        IdentityError::InvalidProtectedHeaders
        | IdentityError::UnprotectedHeadersForbidden
        | IdentityError::MissingPayload
        | IdentityError::NonCanonicalCose
        | IdentityError::Cose(_) => CapabilityV2Error::InvalidApprovalEnvelope,
        _ => CapabilityV2Error::ApprovalVerificationFailed,
    }
}
