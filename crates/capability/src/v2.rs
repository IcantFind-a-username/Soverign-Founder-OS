//! Capability V2: exact, signed authorization for one publisher-verified invocation.
//!
//! This module does not upgrade or accept a V1 token. It accepts only the
//! artifact layer's opaque [`PreparedInvocation`], which prevents callers from
//! inventing digest views that were never prepared by the artifact boundary.
//! Replay and idempotency defense is process-local by default; attaching a
//! durable [`AuthorityStore`] makes consumption survive restarts and
//! concurrent processes. Effectful execution additionally requires crash-safe
//! audit ordering and reviewed host interfaces, which do not exist yet.

use std::collections::{HashMap, HashSet};
use std::fmt;

use chrono::{Duration, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use sovereign_artifact::{
    ArtifactBackend, Digest, PreparedInvocation, RiskClass, CANONICALIZATION_PROFILE,
};
use sovereign_identity::{ApprovalRole, AuthorityRole, IdentityError, RoleTrustStore, TypedSigner};
use sovereign_policy::PolicyAuthorizationV2;

use sovereign_authority::{AuthorityError, AuthorityStore};

use crate::approval::SignedApprovalV1;
use thiserror::Error;
use uuid::Uuid;

pub const CAPABILITY_V2_TYPE: &str = "sovereign.capability";
pub const CAPABILITY_V2_VERSION: u16 = 2;
pub const CAPABILITY_V2_CANONICALIZATION: &str = CANONICALIZATION_PROFILE;
pub const CAPABILITY_V2_MAX_TTL_SECONDS: i64 = 5 * 60;
pub const CAPABILITY_V2_MAX_POLICY_AGE_SECONDS: i64 = 30;
pub const CAPABILITY_V2_MAX_TOKEN_BYTES: usize = 72 * 1024;
const CAPABILITY_V2_MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const POLICY_AUTHORIZATION_DIGEST_DOMAIN: &[u8] =
    b"sovereign.capability.policy-authorization.jcs.v2";
const INVOCATION_FINGERPRINT_DOMAIN: &[u8] = b"sovereign.capability.idempotency-binding.jcs.v2";

/// Capability V2 uses the artifact protocol's risk vocabulary directly.
pub type RiskClassV2 = RiskClass;

/// Capability V2 uses the artifact protocol's backend vocabulary directly.
pub type ExecutionBackendV2 = ArtifactBackend;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolScopeV2 {
    pub tool_id: String,
    pub tool_version: String,
    pub operation: String,
}

/// Summary claim carried by a token issued under RFC 0003 approval evidence.
///
/// This is a reference to the signed approval, not the approval itself: the
/// full COSE object is re-verified at consumption. Tokens for decisions that
/// do not require approval carry an explicit null and any other combination
/// fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEvidenceV2 {
    pub approval_id: Uuid,
    pub approver_subject_id: String,
    pub approved_at_unix: i64,
}

/// Strict canonical payload carried inside an opaque AuthorityRole
/// COSE_Sign1 object. Public fields support inspection only after validation;
/// callers cannot submit this structure directly for execution.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityClaimsV2 {
    pub typ: String,
    pub version: u16,
    pub issuer: String,
    pub issuer_key_id: Digest,
    pub audience: String,
    pub token_id: Uuid,
    pub venture_id: String,
    pub subject_id: String,
    pub session_id: Uuid,
    pub tool: ToolScopeV2,
    pub component_digest: Digest,
    pub manifest_digest: Digest,
    pub canonical_input_digest: Digest,
    pub resource_bindings_digest: Digest,
    pub canonicalization_profile: String,
    pub primary_resource: String,
    pub policy_decision_id: Uuid,
    pub policy_decision_digest: Digest,
    #[serde(deserialize_with = "deserialize_explicit_option")]
    pub approval_evidence: Option<ApprovalEvidenceV2>,
    pub idempotency_key: Uuid,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub max_uses: u32,
    pub risk_class: RiskClassV2,
    pub backend: ExecutionBackendV2,
}

fn deserialize_explicit_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl fmt::Debug for CapabilityClaimsV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityClaimsV2")
            .field("typ", &self.typ)
            .field("version", &self.version)
            .field("token_id", &self.token_id)
            .field("policy_decision_id", &self.policy_decision_id)
            .field("issued_at_unix", &self.issued_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("max_uses", &self.max_uses)
            .field("risk_class", &self.risk_class)
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

/// Untrusted, opaque COSE_Sign1 bytes. Constructing this type grants no trust;
/// only [`CapabilityValidatorV2::authorize_and_consume`] opens it.
#[derive(Clone, PartialEq, Eq)]
pub struct CapabilityTokenV2 {
    cose_sign1: Vec<u8>,
}

impl CapabilityTokenV2 {
    pub fn from_cose_sign1(cose_sign1: Vec<u8>) -> Self {
        Self { cose_sign1 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.cose_sign1
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.cose_sign1
    }
}

impl fmt::Debug for CapabilityTokenV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityTokenV2")
            .field("cose_sign1_bytes", &self.cose_sign1.len())
            .finish_non_exhaustive()
    }
}

/// Clock ownership stays inside the issuer and validator. Callers cannot pass
/// a favorable timestamp to an individual authorization attempt.
pub trait TrustedClock: Send + Sync {
    fn now_unix(&self) -> i64;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl TrustedClock for SystemClock {
    fn now_unix(&self) -> i64 {
        Utc::now().timestamp()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapabilityV2Error {
    #[error("policy denied the prepared invocation")]
    PolicyDenied,
    #[error("approval evidence is required and was not provided")]
    ApprovalEvidenceUnavailable,
    /// Retained for API compatibility; RFC 0003 paths report the precise
    /// `UnexpectedApprovalEvidence` / `ApprovalEvidenceMismatch` variants.
    #[error("approval evidence is unsupported in this Capability V2 stage")]
    UnsupportedApprovalEvidence,
    #[error("policy authorization does not exactly match the prepared invocation: {0}")]
    PolicyAuthorizationMismatch(&'static str),
    #[error("policy authorization was evaluated in the future")]
    PolicyAuthorizationFromFuture,
    #[error("policy authorization is older than the issuance limit")]
    PolicyAuthorizationStale,
    #[error("policy authorization decision id was already consumed by this issuer")]
    PolicyAuthorizationReused,
    #[error("invalid issuer")]
    InvalidIssuer,
    #[error("invalid audience")]
    InvalidAudience,
    #[error("invalid subject")]
    InvalidSubject,
    #[error("invalid venture")]
    InvalidVenture,
    #[error("the prepared invocation has no primary resource binding")]
    MissingPrimaryResource,
    #[error("only publisher-verified pure-compute invocations are permitted")]
    UnsupportedRiskClass,
    #[error("execution backend downgrade or unsupported backend denied")]
    BackendDowngradeDenied,
    #[error("Capability V2 lifetime must be positive and no more than five minutes")]
    InvalidLifetime,
    #[error("Capability V2 max_uses must equal one")]
    InvalidUseLimit,
    #[error("failed to canonicalize Capability V2 protocol data")]
    CanonicalizationFailed,
    #[error("failed to sign Capability V2 claims")]
    SigningFailed,
    #[error("unknown Authority key id")]
    UnknownAuthorityKey,
    #[error("Authority key is revoked")]
    AuthorityKeyRevoked,
    #[error("Authority key is not yet valid")]
    AuthorityKeyNotYetValid,
    #[error("Authority key has expired")]
    AuthorityKeyExpired,
    #[error("Authority issuer mismatch")]
    AuthorityIssuerMismatch,
    #[error("invalid Authority signature")]
    InvalidAuthoritySignature,
    #[error("invalid Capability V2 COSE envelope")]
    InvalidCapabilityEnvelope,
    #[error("Authority trust verification failed")]
    AuthorityTrustFailure,
    #[error("Capability V2 token exceeds the protocol size limit")]
    TokenTooLarge,
    #[error("Capability V2 claims exceed the protocol size limit")]
    ClaimsTooLarge,
    #[error("invalid Capability V2 claims")]
    InvalidClaims,
    #[error("Capability V2 payload is not canonical JCS")]
    NonCanonicalPayload,
    #[error("Capability V2 type mismatch")]
    TypeMismatch,
    #[error("unsupported Capability V2 protocol version")]
    UnsupportedVersion,
    #[error("Capability V2 issuer mismatch")]
    IssuerMismatch,
    #[error("Capability V2 issuer key mismatch")]
    IssuerKeyMismatch,
    #[error("Capability V2 audience mismatch")]
    AudienceMismatch,
    #[error("Capability V2 is not yet valid")]
    NotYetValid,
    #[error("Capability V2 has expired")]
    Expired,
    #[error("Capability V2 venture mismatch")]
    VentureMismatch,
    #[error("Capability V2 subject mismatch")]
    SubjectMismatch,
    #[error("Capability V2 session mismatch")]
    SessionMismatch,
    #[error("prepared invocation mismatch: {0}")]
    InvocationMismatch(&'static str),
    #[error("Capability V2 token replayed in this process")]
    Replay,
    #[error("idempotency key already consumed for the same invocation")]
    IdempotencyReplay,
    #[error("idempotency key reused for a different invocation")]
    IdempotencyConflict,
    #[error("approval evidence supplied for a decision that does not require approval")]
    UnexpectedApprovalEvidence,
    #[error("no approval trust store is configured")]
    ApprovalTrustUnavailable,
    #[error("approval lifetime must be positive and no more than ten minutes")]
    ApprovalLifetimeInvalid,
    #[error("invalid approval claims")]
    InvalidApprovalClaims,
    #[error("approval payload is not canonical JCS")]
    NonCanonicalApproval,
    #[error("approval does not match the presented invocation or decision: {0}")]
    ApprovalMismatch(&'static str),
    #[error("approval has expired")]
    ApprovalExpired,
    #[error("approval is dated in the future")]
    ApprovalFromFuture,
    #[error("approval was already consumed in this process")]
    ApprovalReused,
    #[error("approval evidence in the token does not match the presented approval")]
    ApprovalEvidenceMismatch,
    #[error("approval signing key is not trusted")]
    UnknownApprovalKey,
    #[error("approval issuer mismatch")]
    ApprovalIssuerMismatch,
    #[error("approval signing key is revoked")]
    ApprovalKeyRevoked,
    #[error("approval signing key is not yet valid")]
    ApprovalKeyNotYetValid,
    #[error("approval signing key has expired")]
    ApprovalKeyExpired,
    #[error("invalid approval signature")]
    InvalidApprovalSignature,
    #[error("approval envelope is malformed or non-canonical")]
    InvalidApprovalEnvelope,
    #[error("approval verification failed")]
    ApprovalVerificationFailed,
    #[error("durable authority store unavailable or corrupt; execution denied")]
    AuthorityStoreUnavailable,
}

#[derive(Debug, Clone)]
pub struct CapabilityV2IssueOptions {
    pub ttl: Duration,
    pub idempotency_key: Uuid,
}

impl Default for CapabilityV2IssueOptions {
    fn default() -> Self {
        Self {
            ttl: Duration::minutes(5),
            idempotency_key: Uuid::new_v4(),
        }
    }
}

pub struct CapabilityV2IssueRequest<'a> {
    pub venture_id: &'a str,
    pub subject_id: &'a str,
    pub session_id: Uuid,
    pub policy_decision: &'a PolicyAuthorizationV2,
    pub prepared_invocation: &'a PreparedInvocation,
    pub options: CapabilityV2IssueOptions,
}

#[derive(Debug)]
pub struct CapabilityIssuerV2<C: TrustedClock> {
    signer: TypedSigner<AuthorityRole>,
    audience: String,
    clock: C,
    approvals: Option<ApprovalTrust>,
}

#[derive(Debug)]
struct ApprovalTrust {
    trust: RoleTrustStore<ApprovalRole>,
    expected_issuer: String,
}

impl<C: TrustedClock> CapabilityIssuerV2<C> {
    pub fn new(
        signer: TypedSigner<AuthorityRole>,
        audience: impl Into<String>,
        clock: C,
    ) -> Result<Self, CapabilityV2Error> {
        let audience = audience.into();
        validate_identifier(&audience, CapabilityV2Error::InvalidAudience)?;
        validate_identifier(signer.issuer(), CapabilityV2Error::InvalidIssuer)?;
        Ok(Self {
            signer,
            audience,
            clock,
            approvals: None,
        })
    }

    /// Enable RFC 0003 approval-evidence issuance. Without this, every
    /// approval-required request continues to fail closed.
    pub fn with_approval_trust(
        mut self,
        trust: RoleTrustStore<ApprovalRole>,
        expected_approver_issuer: impl Into<String>,
    ) -> Result<Self, CapabilityV2Error> {
        let expected_issuer = expected_approver_issuer.into();
        validate_identifier(&expected_issuer, CapabilityV2Error::InvalidIssuer)?;
        self.approvals = Some(ApprovalTrust {
            trust,
            expected_issuer,
        });
        Ok(self)
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn issuer(&self) -> &str {
        self.signer.issuer()
    }

    pub fn issue(
        &self,
        request: CapabilityV2IssueRequest<'_>,
    ) -> Result<CapabilityTokenV2, CapabilityV2Error> {
        self.issue_inner(request, None)
    }

    /// Issue for an approval-required decision using RFC 0003 signed
    /// evidence. Fails closed unless an approval trust store is configured
    /// and the evidence binds this exact invocation and decision.
    pub fn issue_approved(
        &self,
        request: CapabilityV2IssueRequest<'_>,
        approval: &SignedApprovalV1,
    ) -> Result<CapabilityTokenV2, CapabilityV2Error> {
        self.issue_inner(request, Some(approval))
    }

    fn issue_inner(
        &self,
        request: CapabilityV2IssueRequest<'_>,
        approval: Option<&SignedApprovalV1>,
    ) -> Result<CapabilityTokenV2, CapabilityV2Error> {
        validate_identifier(request.venture_id, CapabilityV2Error::InvalidVenture)?;
        validate_identifier(request.subject_id, CapabilityV2Error::InvalidSubject)?;
        validate_supported_invocation(request.prepared_invocation)?;
        let issued_at_unix = self.clock.now_unix();
        validate_policy_authorization(
            request.policy_decision,
            &self.audience,
            request.venture_id,
            request.subject_id,
            request.session_id,
            request.options.idempotency_key,
            request.prepared_invocation,
        )?;
        let max_policy_age = if approval.is_some() {
            crate::approval::APPROVAL_MAX_TTL_SECONDS
        } else {
            CAPABILITY_V2_MAX_POLICY_AGE_SECONDS
        };
        validate_policy_freshness(request.policy_decision, issued_at_unix, max_policy_age)?;

        if !request.policy_decision.allowed() {
            return Err(CapabilityV2Error::PolicyDenied);
        }
        let approval_evidence = match (request.policy_decision.requires_approval(), approval) {
            (true, None) => return Err(CapabilityV2Error::ApprovalEvidenceUnavailable),
            (false, Some(_)) => return Err(CapabilityV2Error::UnexpectedApprovalEvidence),
            (false, None) => None,
            (true, Some(approval)) => {
                let trust = self
                    .approvals
                    .as_ref()
                    .ok_or(CapabilityV2Error::ApprovalTrustUnavailable)?;
                let claims = crate::approval::verify_approval(
                    approval,
                    crate::approval::ApprovalVerificationContext {
                        trust: &trust.trust,
                        expected_issuer: &trust.expected_issuer,
                        audience: &self.audience,
                        venture_id: request.venture_id,
                        subject_id: request.subject_id,
                        session_id: request.session_id,
                        policy_decision: request.policy_decision,
                        prepared: request.prepared_invocation,
                        now_unix: issued_at_unix,
                    },
                )?;
                Some(ApprovalEvidenceV2 {
                    approval_id: claims.approval_id,
                    approver_subject_id: claims.approver_subject_id,
                    approved_at_unix: claims.approved_at_unix,
                })
            }
        };

        let ttl_seconds = request.options.ttl.num_seconds();
        if ttl_seconds <= 0 || ttl_seconds > CAPABILITY_V2_MAX_TTL_SECONDS {
            return Err(CapabilityV2Error::InvalidLifetime);
        }
        let expires_at_unix = issued_at_unix
            .checked_add(ttl_seconds)
            .ok_or(CapabilityV2Error::InvalidLifetime)?;
        let prepared = request.prepared_invocation;
        let operation = prepared.operation();
        let primary_resource = required_primary_resource(prepared)?;

        let claims = CapabilityClaimsV2 {
            typ: CAPABILITY_V2_TYPE.to_owned(),
            version: CAPABILITY_V2_VERSION,
            issuer: self.signer.issuer().to_owned(),
            issuer_key_id: Digest::from_bytes(*self.signer.key_id()),
            audience: self.audience.clone(),
            token_id: Uuid::new_v4(),
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
            canonicalization_profile: CAPABILITY_V2_CANONICALIZATION.to_owned(),
            primary_resource: primary_resource.to_owned(),
            policy_decision_id: request.policy_decision.decision_id(),
            policy_decision_digest: policy_decision_digest(request.policy_decision)?,
            approval_evidence,
            idempotency_key: request.options.idempotency_key,
            issued_at_unix,
            expires_at_unix,
            max_uses: 1,
            risk_class: prepared.artifact().manifest().risk_class(),
            backend: prepared.artifact().manifest().backend(),
        };
        let canonical_payload = canonical_claims(&claims)?;
        if canonical_payload.len() > CAPABILITY_V2_MAX_PAYLOAD_BYTES {
            return Err(CapabilityV2Error::ClaimsTooLarge);
        }
        let cose_sign1 = self
            .signer
            .sign_cose(&canonical_payload)
            .map_err(|_| CapabilityV2Error::SigningFailed)?;
        if cose_sign1.len() > CAPABILITY_V2_MAX_TOKEN_BYTES {
            return Err(CapabilityV2Error::TokenTooLarge);
        }
        Ok(CapabilityTokenV2 { cose_sign1 })
    }
}

pub struct CapabilityV2ValidationContext<'a> {
    pub venture_id: &'a str,
    pub subject_id: &'a str,
    pub session_id: Uuid,
    pub policy_decision: &'a PolicyAuthorizationV2,
    pub prepared_invocation: &'a PreparedInvocation,
}

#[derive(Debug)]
pub struct CapabilityValidatorV2<C: TrustedClock> {
    trust_store: RoleTrustStore<AuthorityRole>,
    expected_issuer: String,
    expected_audience: String,
    clock: C,
    consumed_tokens: HashSet<Uuid>,
    idempotency: HashMap<Uuid, Digest>,
    approvals: Option<ApprovalTrust>,
    consumed_approvals: HashSet<Uuid>,
    authority_store: Option<AuthorityStore>,
}

impl<C: TrustedClock> CapabilityValidatorV2<C> {
    pub fn new(
        trust_store: RoleTrustStore<AuthorityRole>,
        expected_issuer: impl Into<String>,
        expected_audience: impl Into<String>,
        clock: C,
    ) -> Result<Self, CapabilityV2Error> {
        let expected_issuer = expected_issuer.into();
        let expected_audience = expected_audience.into();
        validate_identifier(&expected_issuer, CapabilityV2Error::InvalidIssuer)?;
        validate_identifier(&expected_audience, CapabilityV2Error::InvalidAudience)?;
        Ok(Self {
            trust_store,
            expected_issuer,
            expected_audience,
            clock,
            consumed_tokens: HashSet::new(),
            idempotency: HashMap::new(),
            approvals: None,
            consumed_approvals: HashSet::new(),
            authority_store: None,
        })
    }

    /// Enable RFC 0003 approval-evidence validation. Without this, every
    /// token carrying approval evidence continues to fail closed.
    pub fn with_approval_trust(
        mut self,
        trust: RoleTrustStore<ApprovalRole>,
        expected_approver_issuer: impl Into<String>,
    ) -> Result<Self, CapabilityV2Error> {
        let expected_issuer = expected_approver_issuer.into();
        validate_identifier(&expected_issuer, CapabilityV2Error::InvalidIssuer)?;
        self.approvals = Some(ApprovalTrust {
            trust,
            expected_issuer,
        });
        Ok(self)
    }

    /// Attach a durable Authority Store. Consumption of tokens, approvals,
    /// and idempotency keys then survives restarts and concurrent processes;
    /// a store failure denies execution (fail closed). Without a store,
    /// replay defense remains process-local, as documented.
    pub fn with_authority_store(mut self, store: AuthorityStore) -> Self {
        self.authority_store = Some(store);
        self
    }

    /// Verify every binding and consume the one-use token before guest startup.
    /// State is intentionally process-local and is not sufficient for external
    /// effects or multi-process execution.
    pub fn authorize_and_consume(
        &mut self,
        token: &CapabilityTokenV2,
        context: CapabilityV2ValidationContext<'_>,
    ) -> Result<AuthorizedCapabilityV2, CapabilityV2Error> {
        self.authorize_and_consume_approved(token, context, None)
    }

    /// Like [`Self::authorize_and_consume`], additionally presenting the RFC
    /// 0003 signed approval whenever the token carries approval evidence.
    /// Both sides are re-verified so consumption observes the same evidence
    /// bytes that issuance did; the approval id is consumed at most once per
    /// process.
    pub fn authorize_and_consume_approved(
        &mut self,
        token: &CapabilityTokenV2,
        context: CapabilityV2ValidationContext<'_>,
        approval: Option<&SignedApprovalV1>,
    ) -> Result<AuthorizedCapabilityV2, CapabilityV2Error> {
        if token.as_bytes().len() > CAPABILITY_V2_MAX_TOKEN_BYTES {
            return Err(CapabilityV2Error::TokenTooLarge);
        }
        let now_unix = self.clock.now_unix();
        let verified = self
            .trust_store
            .verify(token.as_bytes(), &self.expected_issuer, now_unix)
            .map_err(map_identity_error)?;
        if verified.payload().len() > CAPABILITY_V2_MAX_PAYLOAD_BYTES {
            return Err(CapabilityV2Error::ClaimsTooLarge);
        }
        let claims: CapabilityClaimsV2 = serde_json::from_slice(verified.payload())
            .map_err(|_| CapabilityV2Error::InvalidClaims)?;
        let canonical = canonical_claims(&claims)?;
        if canonical != verified.payload() {
            return Err(CapabilityV2Error::NonCanonicalPayload);
        }

        if claims.typ != CAPABILITY_V2_TYPE {
            return Err(CapabilityV2Error::TypeMismatch);
        }
        if claims.version != CAPABILITY_V2_VERSION {
            return Err(CapabilityV2Error::UnsupportedVersion);
        }
        if claims.issuer != self.expected_issuer || verified.issuer() != self.expected_issuer {
            return Err(CapabilityV2Error::IssuerMismatch);
        }
        if claims.issuer_key_id.as_bytes() != verified.key_id() {
            return Err(CapabilityV2Error::IssuerKeyMismatch);
        }
        if claims.audience != self.expected_audience {
            return Err(CapabilityV2Error::AudienceMismatch);
        }
        validate_claim_lifetime(&claims, now_unix)?;
        if claims.max_uses != 1 {
            return Err(CapabilityV2Error::InvalidUseLimit);
        }
        if claims.risk_class != RiskClass::PureCompute {
            return Err(CapabilityV2Error::UnsupportedRiskClass);
        }
        if claims.backend != ArtifactBackend::CoreWasm {
            return Err(CapabilityV2Error::BackendDowngradeDenied);
        }
        if claims.venture_id != context.venture_id {
            return Err(CapabilityV2Error::VentureMismatch);
        }
        if claims.subject_id != context.subject_id {
            return Err(CapabilityV2Error::SubjectMismatch);
        }
        if claims.session_id != context.session_id {
            return Err(CapabilityV2Error::SessionMismatch);
        }

        validate_supported_invocation(context.prepared_invocation)?;
        compare_invocation_claims(&claims, context.prepared_invocation)?;
        validate_policy_authorization(
            context.policy_decision,
            &self.expected_audience,
            context.venture_id,
            context.subject_id,
            context.session_id,
            claims.idempotency_key,
            context.prepared_invocation,
        )?;
        let max_policy_age = if claims.approval_evidence.is_some() {
            crate::approval::APPROVAL_MAX_TTL_SECONDS
        } else {
            CAPABILITY_V2_MAX_POLICY_AGE_SECONDS
        };
        validate_policy_freshness(context.policy_decision, now_unix, max_policy_age)?;
        if !context.policy_decision.allowed() {
            return Err(CapabilityV2Error::PolicyDenied);
        }
        if claims.policy_decision_id != context.policy_decision.decision_id()
            || claims.policy_decision_digest != policy_decision_digest(context.policy_decision)?
        {
            return Err(CapabilityV2Error::PolicyAuthorizationMismatch(
                "decision_digest",
            ));
        }

        if self.consumed_tokens.contains(&claims.token_id) {
            return Err(CapabilityV2Error::Replay);
        }

        // RFC 0003: the token's evidence claim, the presented signed object,
        // and the policy requirement must all agree. Any partial combination
        // fails closed.
        let approval_id = match (
            context.policy_decision.requires_approval(),
            &claims.approval_evidence,
            approval,
        ) {
            (false, None, None) => None,
            (true, None, _) => return Err(CapabilityV2Error::ApprovalEvidenceUnavailable),
            (false, _, Some(_)) | (false, Some(_), None) => {
                return Err(CapabilityV2Error::UnexpectedApprovalEvidence)
            }
            (true, Some(_), None) => return Err(CapabilityV2Error::ApprovalEvidenceMismatch),
            (true, Some(evidence), Some(approval)) => {
                let trust = self
                    .approvals
                    .as_ref()
                    .ok_or(CapabilityV2Error::ApprovalTrustUnavailable)?;
                let verified = crate::approval::verify_approval(
                    approval,
                    crate::approval::ApprovalVerificationContext {
                        trust: &trust.trust,
                        expected_issuer: &trust.expected_issuer,
                        audience: &self.expected_audience,
                        venture_id: context.venture_id,
                        subject_id: context.subject_id,
                        session_id: context.session_id,
                        policy_decision: context.policy_decision,
                        prepared: context.prepared_invocation,
                        now_unix,
                    },
                )?;
                if verified.approval_id != evidence.approval_id
                    || verified.approver_subject_id != evidence.approver_subject_id
                    || verified.approved_at_unix != evidence.approved_at_unix
                {
                    return Err(CapabilityV2Error::ApprovalEvidenceMismatch);
                }
                if self.consumed_approvals.contains(&verified.approval_id) {
                    return Err(CapabilityV2Error::ApprovalReused);
                }
                Some(verified.approval_id)
            }
        };

        let fingerprint = invocation_fingerprint(&claims)?;
        if let Some(existing) = self.idempotency.get(&claims.idempotency_key) {
            if *existing == fingerprint {
                return Err(CapabilityV2Error::IdempotencyReplay);
            }
            return Err(CapabilityV2Error::IdempotencyConflict);
        }

        // Durable claims come after every validation and before the
        // process-local bookkeeping. A partial failure burns the earlier
        // claims and denies the request: fail closed, never fail open.
        if let Some(store) = &self.authority_store {
            store
                .consume_token(claims.token_id, now_unix, claims.expires_at_unix)
                .map_err(map_authority_error_token)?;
            store
                .bind_idempotency(
                    claims.idempotency_key,
                    fingerprint.as_bytes(),
                    now_unix,
                    claims.expires_at_unix,
                )
                .map_err(map_authority_error_idempotency)?;
            if let Some(approval_id) = approval_id {
                store
                    .consume_approval(approval_id, now_unix, claims.expires_at_unix)
                    .map_err(map_authority_error_approval)?;
            }
        }

        self.consumed_tokens.insert(claims.token_id);
        self.idempotency.insert(claims.idempotency_key, fingerprint);
        if let Some(approval_id) = approval_id {
            self.consumed_approvals.insert(approval_id);
        }
        Ok(AuthorizedCapabilityV2 { claims })
    }
}

/// Proof that cryptographic, temporal, policy, artifact, invocation, replay,
/// and idempotency checks succeeded and the process-local use was consumed.
#[derive(Debug, Clone)]
pub struct AuthorizedCapabilityV2 {
    claims: CapabilityClaimsV2,
}

impl AuthorizedCapabilityV2 {
    pub fn claims(&self) -> &CapabilityClaimsV2 {
        &self.claims
    }

    pub fn token_id(&self) -> Uuid {
        self.claims.token_id
    }

    pub fn idempotency_key(&self) -> Uuid {
        self.claims.idempotency_key
    }
}

pub fn policy_decision_digest(
    decision: &PolicyAuthorizationV2,
) -> Result<Digest, CapabilityV2Error> {
    let canonical = serde_json_canonicalizer::to_vec(decision)
        .map_err(|_| CapabilityV2Error::CanonicalizationFailed)?;
    Ok(Digest::domain_separated(
        POLICY_AUTHORIZATION_DIGEST_DOMAIN,
        &canonical,
    ))
}

fn canonical_claims(claims: &CapabilityClaimsV2) -> Result<Vec<u8>, CapabilityV2Error> {
    serde_json_canonicalizer::to_vec(claims).map_err(|_| CapabilityV2Error::CanonicalizationFailed)
}

fn invocation_fingerprint(claims: &CapabilityClaimsV2) -> Result<Digest, CapabilityV2Error> {
    #[derive(Serialize)]
    struct Fingerprint<'a> {
        audience: &'a str,
        venture_id: &'a str,
        subject_id: &'a str,
        session_id: Uuid,
        tool: &'a ToolScopeV2,
        component_digest: Digest,
        manifest_digest: Digest,
        canonical_input_digest: Digest,
        resource_bindings_digest: Digest,
        canonicalization_profile: &'a str,
        primary_resource: &'a str,
        policy_decision_digest: Digest,
        risk_class: RiskClassV2,
        backend: ExecutionBackendV2,
    }

    let body = Fingerprint {
        audience: &claims.audience,
        venture_id: &claims.venture_id,
        subject_id: &claims.subject_id,
        session_id: claims.session_id,
        tool: &claims.tool,
        component_digest: claims.component_digest,
        manifest_digest: claims.manifest_digest,
        canonical_input_digest: claims.canonical_input_digest,
        resource_bindings_digest: claims.resource_bindings_digest,
        canonicalization_profile: &claims.canonicalization_profile,
        primary_resource: &claims.primary_resource,
        policy_decision_digest: claims.policy_decision_digest,
        risk_class: claims.risk_class,
        backend: claims.backend,
    };
    let canonical = serde_json_canonicalizer::to_vec(&body)
        .map_err(|_| CapabilityV2Error::CanonicalizationFailed)?;
    Ok(Digest::domain_separated(
        INVOCATION_FINGERPRINT_DOMAIN,
        &canonical,
    ))
}

fn validate_claim_lifetime(
    claims: &CapabilityClaimsV2,
    now_unix: i64,
) -> Result<(), CapabilityV2Error> {
    let lifetime = claims
        .expires_at_unix
        .checked_sub(claims.issued_at_unix)
        .ok_or(CapabilityV2Error::InvalidLifetime)?;
    if lifetime <= 0 || lifetime > CAPABILITY_V2_MAX_TTL_SECONDS {
        return Err(CapabilityV2Error::InvalidLifetime);
    }
    if now_unix < claims.issued_at_unix {
        return Err(CapabilityV2Error::NotYetValid);
    }
    if now_unix >= claims.expires_at_unix {
        return Err(CapabilityV2Error::Expired);
    }
    Ok(())
}

fn validate_supported_invocation(prepared: &PreparedInvocation) -> Result<(), CapabilityV2Error> {
    if prepared.artifact().manifest().risk_class() != RiskClass::PureCompute {
        return Err(CapabilityV2Error::UnsupportedRiskClass);
    }
    if prepared.artifact().manifest().backend() != ArtifactBackend::CoreWasm {
        return Err(CapabilityV2Error::BackendDowngradeDenied);
    }
    let primary_resource = required_primary_resource(prepared)?;
    validate_identifier(primary_resource, CapabilityV2Error::MissingPrimaryResource)?;
    Ok(())
}

fn required_primary_resource(prepared: &PreparedInvocation) -> Result<&str, CapabilityV2Error> {
    prepared
        .primary_resource()
        .ok_or(CapabilityV2Error::MissingPrimaryResource)
}

fn validate_policy_authorization(
    decision: &PolicyAuthorizationV2,
    audience: &str,
    venture_id: &str,
    subject_id: &str,
    session_id: Uuid,
    idempotency_key: Uuid,
    prepared: &PreparedInvocation,
) -> Result<(), CapabilityV2Error> {
    if decision.audience() != audience {
        return Err(CapabilityV2Error::PolicyAuthorizationMismatch("audience"));
    }
    if decision.venture_id() != venture_id {
        return Err(CapabilityV2Error::PolicyAuthorizationMismatch("venture_id"));
    }
    if decision.subject_id() != subject_id {
        return Err(CapabilityV2Error::PolicyAuthorizationMismatch("subject_id"));
    }
    if decision.session_id() != session_id {
        return Err(CapabilityV2Error::PolicyAuthorizationMismatch("session_id"));
    }
    if decision.idempotency_key() != idempotency_key {
        return Err(CapabilityV2Error::PolicyAuthorizationMismatch(
            "idempotency_key",
        ));
    }
    if decision.tool_id() != prepared.operation().tool_id() {
        return Err(CapabilityV2Error::PolicyAuthorizationMismatch("tool_id"));
    }
    if decision.operation() != prepared.operation().operation_id() {
        return Err(CapabilityV2Error::PolicyAuthorizationMismatch("operation"));
    }
    if decision.tool_version() != prepared.operation().tool_version() {
        return Err(CapabilityV2Error::PolicyAuthorizationMismatch(
            "tool_version",
        ));
    }
    if decision.primary_resource() != required_primary_resource(prepared)? {
        return Err(CapabilityV2Error::PolicyAuthorizationMismatch(
            "primary_resource",
        ));
    }
    let artifact = prepared.artifact();
    let digest_checks = [
        (
            "component_digest",
            decision.component_digest(),
            artifact.component_digest(),
        ),
        (
            "manifest_digest",
            decision.manifest_digest(),
            artifact.manifest_digest(),
        ),
        (
            "canonical_input_digest",
            decision.canonical_input_digest(),
            prepared.input_digest(),
        ),
        (
            "resource_bindings_digest",
            decision.resource_bindings_digest(),
            prepared.bindings_digest(),
        ),
    ];
    for (field, authorized, actual) in digest_checks {
        if authorized != actual {
            return Err(CapabilityV2Error::PolicyAuthorizationMismatch(field));
        }
    }
    if decision.canonicalization_profile() != CAPABILITY_V2_CANONICALIZATION {
        return Err(CapabilityV2Error::PolicyAuthorizationMismatch(
            "canonicalization_profile",
        ));
    }
    if decision.risk_class() != artifact.manifest().risk_class() {
        return Err(CapabilityV2Error::PolicyAuthorizationMismatch("risk_class"));
    }
    if decision.backend() != artifact.manifest().backend() {
        return Err(CapabilityV2Error::PolicyAuthorizationMismatch("backend"));
    }
    Ok(())
}

/// The default freshness window is tight because unattended issuance should
/// be immediate. With verified approval evidence, RFC 0003 extends the window
/// to the approval TTL: a human cannot review and click within 30 seconds,
/// and the signed approval attests review of that exact decision.
fn validate_policy_freshness(
    decision: &PolicyAuthorizationV2,
    now_unix: i64,
    max_age_seconds: i64,
) -> Result<(), CapabilityV2Error> {
    let age = now_unix
        .checked_sub(decision.evaluated_at_unix())
        .ok_or(CapabilityV2Error::PolicyAuthorizationFromFuture)?;
    if age < 0 {
        return Err(CapabilityV2Error::PolicyAuthorizationFromFuture);
    }
    if age > max_age_seconds {
        return Err(CapabilityV2Error::PolicyAuthorizationStale);
    }
    Ok(())
}

fn compare_invocation_claims(
    claims: &CapabilityClaimsV2,
    prepared: &PreparedInvocation,
) -> Result<(), CapabilityV2Error> {
    let operation = prepared.operation();
    let text_checks = [
        ("tool_id", claims.tool.tool_id.as_str(), operation.tool_id()),
        (
            "tool_version",
            claims.tool.tool_version.as_str(),
            operation.tool_version(),
        ),
        (
            "operation",
            claims.tool.operation.as_str(),
            operation.operation_id(),
        ),
        (
            "canonicalization_profile",
            claims.canonicalization_profile.as_str(),
            CAPABILITY_V2_CANONICALIZATION,
        ),
        (
            "primary_resource",
            claims.primary_resource.as_str(),
            required_primary_resource(prepared)?,
        ),
    ];
    for (name, claim, actual) in text_checks {
        if claim != actual {
            return Err(CapabilityV2Error::InvocationMismatch(name));
        }
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
    for (name, claim, actual) in digest_checks {
        if claim != actual {
            return Err(CapabilityV2Error::InvocationMismatch(name));
        }
    }
    if claims.risk_class != prepared.artifact().manifest().risk_class() {
        return Err(CapabilityV2Error::InvocationMismatch("risk_class"));
    }
    if claims.backend != prepared.artifact().manifest().backend() {
        return Err(CapabilityV2Error::InvocationMismatch("backend"));
    }
    Ok(())
}

fn map_authority_error_token(error: AuthorityError) -> CapabilityV2Error {
    match error {
        AuthorityError::AlreadyConsumed => CapabilityV2Error::Replay,
        _ => CapabilityV2Error::AuthorityStoreUnavailable,
    }
}

fn map_authority_error_idempotency(error: AuthorityError) -> CapabilityV2Error {
    match error {
        AuthorityError::IdempotencyReplay => CapabilityV2Error::IdempotencyReplay,
        AuthorityError::IdempotencyConflict => CapabilityV2Error::IdempotencyConflict,
        _ => CapabilityV2Error::AuthorityStoreUnavailable,
    }
}

fn map_authority_error_approval(error: AuthorityError) -> CapabilityV2Error {
    match error {
        AuthorityError::AlreadyConsumed => CapabilityV2Error::ApprovalReused,
        _ => CapabilityV2Error::AuthorityStoreUnavailable,
    }
}

fn map_identity_error(error: IdentityError) -> CapabilityV2Error {
    match error {
        IdentityError::UnknownKeyId => CapabilityV2Error::UnknownAuthorityKey,
        IdentityError::IssuerMismatch | IdentityError::InvalidIssuer => {
            CapabilityV2Error::AuthorityIssuerMismatch
        }
        IdentityError::KeyRevoked => CapabilityV2Error::AuthorityKeyRevoked,
        IdentityError::KeyNotYetValid => CapabilityV2Error::AuthorityKeyNotYetValid,
        IdentityError::KeyExpired => CapabilityV2Error::AuthorityKeyExpired,
        IdentityError::VerificationFailed => CapabilityV2Error::InvalidAuthoritySignature,
        IdentityError::InvalidProtectedHeaders
        | IdentityError::UnprotectedHeadersForbidden
        | IdentityError::MissingPayload
        | IdentityError::NonCanonicalCose
        | IdentityError::Cose(_) => CapabilityV2Error::InvalidCapabilityEnvelope,
        _ => CapabilityV2Error::AuthorityTrustFailure,
    }
}

fn validate_identifier(value: &str, error: CapabilityV2Error) -> Result<(), CapabilityV2Error> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > 512
        || value.chars().any(char::is_control)
    {
        return Err(error);
    }
    Ok(())
}
