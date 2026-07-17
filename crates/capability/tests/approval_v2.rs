//! Adversarial tests for RFC 0003 signed approval evidence: exact binding,
//! role separation, temporal rules, one-use consumption, and fail-closed
//! behavior for every partial combination of evidence.

use chrono::{DateTime, Duration, Utc};
use sovereign_artifact::{
    AdmissionLimits, ArtifactVerificationIntent, ArtifactVerifier, Digest, OperationSelector,
    PreparedInvocation, RawResourceGrant, TrustedClock as ArtifactClock, CORE_WASM_ENTRYPOINT,
    MANIFEST_PROTOCOL_VERSION,
};
use sovereign_capability::approval::{
    approve_invocation, ApprovalGrantRequest, SignedApprovalV1, APPROVAL_MAX_TTL_SECONDS,
};
use sovereign_capability::v2::{
    CapabilityIssuerV2, CapabilityTokenV2, CapabilityV2Error, CapabilityV2IssueOptions,
    CapabilityV2IssueRequest, CapabilityV2ValidationContext, CapabilityValidatorV2, TrustedClock,
};
use sovereign_contracts::{AutomationLevel, DataClass};
use sovereign_identity::{
    ApprovalRole, AuthorityRole, KeyValidity, PublisherRole, RoleTrustStore, TypedSigner,
};
use sovereign_policy::{AuthenticatedPolicyContextV2, PolicyAuthorizationV2, PolicyEngine};
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;
const AUTHORITY_ISSUER: &str = "authority.local";
const APPROVER_ISSUER: &str = "owner-approval.local";
const PUBLISHER_ISSUER: &str = "publisher.local";
const AUDIENCE: &str = "sovereign-runtime";
const VENTURE: &str = "venture-alpha";
const SUBJECT: &str = "founder-session-subject";
const APPROVER: &str = "human-owner";
const RESOURCE: &str = "draft:alpha";
const AUTHORITY_SECRET: [u8; 32] = [0x41; 32];
const APPROVER_SECRET: [u8; 32] = [0x42; 32];
const PUBLISHER_SECRET: [u8; 32] = [0x50; 32];
const SESSION: Uuid = Uuid::from_u128(7);

#[derive(Debug, Clone, Copy)]
struct FixedClock(i64);

impl TrustedClock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.0
    }
}

impl ArtifactClock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.0
    }
}

impl sovereign_policy::TrustedClock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(self.0, 0).unwrap()
    }
}

fn selector() -> OperationSelector {
    OperationSelector::new("document.transform", "1.0.0", "render").unwrap()
}

fn prepared(content: &str) -> PreparedInvocation {
    let publisher =
        TypedSigner::<PublisherRole>::from_secret_bytes(PUBLISHER_ISSUER, PUBLISHER_SECRET)
            .unwrap();
    let component: &[u8] = b"\0asm\x01\0\0\0approval-fixture";
    let manifest = serde_json::json!({
        "protocol_version": MANIFEST_PROTOCOL_VERSION,
        "publisher_issuer": PUBLISHER_ISSUER,
        "publisher_key_id": Digest::from_bytes(*publisher.key_id()),
        "component_digest": Digest::of_bytes(component),
        "backend": "core_wasm",
        "risk_class": "pure_compute",
        "abi": "sovereign_core_wasm_v1",
        "entrypoint": CORE_WASM_ENTRYPOINT,
        "requested_host_capabilities": [],
        "operations": [{
            "selector": {
                "tool_id": "document.transform",
                "tool_version": "1.0.0",
                "operation_id": "render"
            },
            "input_limits": { "max_bytes": 4096, "max_depth": 8 },
            "input_schema": {
                "type": "object",
                "properties": {
                    "content": { "type": "string", "max_utf8_bytes": 2048 },
                    "resource": { "type": "string", "max_utf8_bytes": 256 }
                },
                "required": ["content", "resource"],
                "max_properties": 2
            },
            "resource_bindings": [{
                "binding_id": "primary",
                "json_pointer": "/resource",
                "normalization": "exact_utf8_v1",
                "primary": true
            }]
        }]
    });
    let canonical = serde_json_canonicalizer::to_vec(&manifest).unwrap();
    let signed = publisher.sign_cose(&canonical).unwrap();
    let mut publishers = RoleTrustStore::<PublisherRole>::new();
    publishers
        .trust_signer(&publisher, KeyValidity::new(NOW - 60, NOW + 7_200).unwrap())
        .unwrap();
    let intent = ArtifactVerificationIntent::new(
        PUBLISHER_ISSUER,
        Digest::of_bytes(&signed),
        Digest::of_bytes(component),
    )
    .unwrap();
    let artifact =
        ArtifactVerifier::with_clock(&publishers, AdmissionLimits::default(), FixedClock(NOW))
            .verify(&intent, &signed, component)
            .unwrap();
    let input = serde_json::to_vec(&serde_json::json!({
        "content": content,
        "resource": RESOURCE
    }))
    .unwrap();
    PreparedInvocation::prepare(
        &artifact,
        &selector(),
        &input,
        vec![RawResourceGrant::new("primary", RESOURCE)],
    )
    .unwrap()
}

fn decision(
    invocation: &PreparedInvocation,
    level: AutomationLevel,
    idempotency: Uuid,
) -> PolicyAuthorizationV2 {
    PolicyEngine::with_clock(FixedClock(NOW))
        .evaluate_prepared(
            invocation,
            AuthenticatedPolicyContextV2::new(
                AUDIENCE,
                VENTURE,
                SUBJECT,
                SESSION,
                DataClass::Green,
                level,
                idempotency,
            )
            .unwrap(),
        )
        .unwrap()
}

fn approver() -> TypedSigner<ApprovalRole> {
    TypedSigner::<ApprovalRole>::from_secret_bytes(APPROVER_ISSUER, APPROVER_SECRET).unwrap()
}

fn approval_trust() -> RoleTrustStore<ApprovalRole> {
    let mut trust = RoleTrustStore::<ApprovalRole>::new();
    trust
        .trust_signer(
            &approver(),
            KeyValidity::new(NOW - 60, NOW + 7_200).unwrap(),
        )
        .unwrap();
    trust
}

fn issuer_at(now: i64) -> CapabilityIssuerV2<FixedClock> {
    CapabilityIssuerV2::new(
        TypedSigner::<AuthorityRole>::from_secret_bytes(AUTHORITY_ISSUER, AUTHORITY_SECRET)
            .unwrap(),
        AUDIENCE,
        FixedClock(now),
    )
    .unwrap()
    .with_approval_trust(approval_trust(), APPROVER_ISSUER)
    .unwrap()
}

fn validator_at(now: i64) -> CapabilityValidatorV2<FixedClock> {
    let trusted =
        TypedSigner::<AuthorityRole>::from_secret_bytes(AUTHORITY_ISSUER, AUTHORITY_SECRET)
            .unwrap();
    let mut authority_trust = RoleTrustStore::<AuthorityRole>::new();
    authority_trust
        .trust_signer(&trusted, KeyValidity::new(NOW - 60, NOW + 7_200).unwrap())
        .unwrap();
    CapabilityValidatorV2::new(authority_trust, AUTHORITY_ISSUER, AUDIENCE, FixedClock(now))
        .unwrap()
        .with_approval_trust(approval_trust(), APPROVER_ISSUER)
        .unwrap()
}

fn approve_at(
    now: i64,
    invocation: &PreparedInvocation,
    policy_decision: &PolicyAuthorizationV2,
    ttl_seconds: i64,
) -> SignedApprovalV1 {
    approve_invocation(
        &approver(),
        &FixedClock(now),
        ApprovalGrantRequest {
            approver_subject_id: APPROVER,
            audience: AUDIENCE,
            venture_id: VENTURE,
            subject_id: SUBJECT,
            session_id: SESSION,
            policy_decision,
            prepared_invocation: invocation,
            ttl_seconds,
        },
    )
    .unwrap()
}

fn request<'a>(
    invocation: &'a PreparedInvocation,
    policy_decision: &'a PolicyAuthorizationV2,
    idempotency: Uuid,
) -> CapabilityV2IssueRequest<'a> {
    CapabilityV2IssueRequest {
        venture_id: VENTURE,
        subject_id: SUBJECT,
        session_id: SESSION,
        policy_decision,
        prepared_invocation: invocation,
        options: CapabilityV2IssueOptions {
            ttl: Duration::seconds(60),
            idempotency_key: idempotency,
        },
    }
}

fn context<'a>(
    invocation: &'a PreparedInvocation,
    policy_decision: &'a PolicyAuthorizationV2,
) -> CapabilityV2ValidationContext<'a> {
    CapabilityV2ValidationContext {
        venture_id: VENTURE,
        subject_id: SUBJECT,
        session_id: SESSION,
        policy_decision,
        prepared_invocation: invocation,
    }
}

fn consume(
    validator: &mut CapabilityValidatorV2<FixedClock>,
    token: &CapabilityTokenV2,
    invocation: &PreparedInvocation,
    policy_decision: &PolicyAuthorizationV2,
    approval: Option<&SignedApprovalV1>,
) -> Result<(), CapabilityV2Error> {
    validator
        .authorize_and_consume_approved(token, context(invocation, policy_decision), approval)
        .map(|_| ())
}

#[test]
fn approved_high_impact_invocation_issues_and_consumes_once() {
    let invocation = prepared("approved input");
    let idempotency = Uuid::from_u128(11);
    let policy_decision = decision(&invocation, AutomationLevel::L3BoundedAuto, idempotency);
    assert!(policy_decision.requires_approval());

    // The human approves 2 minutes after evaluation; issuance happens after
    // that, well beyond the 30-second unattended window.
    let approval = approve_at(NOW + 120, &invocation, &policy_decision, 300);
    let issuer = issuer_at(NOW + 125);
    let token = issuer
        .issue_approved(
            request(&invocation, &policy_decision, idempotency),
            &approval,
        )
        .unwrap();

    let mut validator = validator_at(NOW + 130);
    consume(
        &mut validator,
        &token,
        &invocation,
        &policy_decision,
        Some(&approval),
    )
    .unwrap();

    // The token is consumed; so is the approval.
    assert_eq!(
        consume(
            &mut validator,
            &token,
            &invocation,
            &policy_decision,
            Some(&approval),
        )
        .unwrap_err(),
        CapabilityV2Error::Replay
    );
}

#[test]
fn plain_issue_still_fails_closed_without_evidence() {
    let invocation = prepared("approved input");
    let idempotency = Uuid::from_u128(12);
    let policy_decision = decision(&invocation, AutomationLevel::L3BoundedAuto, idempotency);
    let issuer = issuer_at(NOW + 5);
    assert_eq!(
        issuer
            .issue(request(&invocation, &policy_decision, idempotency))
            .unwrap_err(),
        CapabilityV2Error::ApprovalEvidenceUnavailable
    );
}

#[test]
fn approval_is_bound_to_the_exact_invocation_and_decision() {
    let invocation = prepared("authorized input");
    let other_invocation = prepared("different input");
    let idempotency = Uuid::from_u128(13);
    let policy_decision = decision(&invocation, AutomationLevel::L3BoundedAuto, idempotency);
    let other_decision = decision(
        &other_invocation,
        AutomationLevel::L3BoundedAuto,
        Uuid::from_u128(14),
    );
    let issuer = issuer_at(NOW + 10);

    // Approval signed for a different invocation.
    let wrong_invocation_approval = approve_at(NOW + 5, &other_invocation, &other_decision, 300);
    assert_eq!(
        issuer
            .issue_approved(
                request(&invocation, &policy_decision, idempotency),
                &wrong_invocation_approval,
            )
            .unwrap_err(),
        CapabilityV2Error::ApprovalMismatch("canonical_input_digest")
    );

    // Approval for the right invocation but a different policy decision.
    let wrong_decision_approval = approve_at(NOW + 5, &invocation, &other_decision, 300);
    assert_eq!(
        issuer
            .issue_approved(
                request(&invocation, &policy_decision, idempotency),
                &wrong_decision_approval,
            )
            .unwrap_err(),
        CapabilityV2Error::ApprovalMismatch("policy_decision")
    );
}

#[test]
fn forged_untrusted_and_cross_role_approvals_are_rejected() {
    let invocation = prepared("authorized input");
    let idempotency = Uuid::from_u128(15);
    let policy_decision = decision(&invocation, AutomationLevel::L3BoundedAuto, idempotency);
    let issuer = issuer_at(NOW + 10);

    // Untrusted approval key.
    let stranger =
        TypedSigner::<ApprovalRole>::from_secret_bytes("stranger.local", [0x99; 32]).unwrap();
    let forged = approve_invocation(
        &stranger,
        &FixedClock(NOW + 5),
        ApprovalGrantRequest {
            approver_subject_id: APPROVER,
            audience: AUDIENCE,
            venture_id: VENTURE,
            subject_id: SUBJECT,
            session_id: SESSION,
            policy_decision: &policy_decision,
            prepared_invocation: &invocation,
            ttl_seconds: 300,
        },
    )
    .unwrap();
    assert_eq!(
        issuer
            .issue_approved(request(&invocation, &policy_decision, idempotency), &forged)
            .unwrap_err(),
        CapabilityV2Error::UnknownApprovalKey
    );

    // Same secret bytes signing under the authority role must not verify as
    // an approval: the role domain separates them.
    let authority_role_signer =
        TypedSigner::<AuthorityRole>::from_secret_bytes(APPROVER_ISSUER, APPROVER_SECRET).unwrap();
    let real = approve_at(NOW + 5, &invocation, &policy_decision, 300);
    let real_claims: serde_json::Value = {
        // Re-sign the same canonical claims under the wrong role.
        let verified = approval_trust()
            .verify(real.as_bytes(), APPROVER_ISSUER, NOW + 6)
            .unwrap();
        serde_json::from_slice(verified.payload()).unwrap()
    };
    let cross_role_bytes = authority_role_signer
        .sign_cose(&serde_json_canonicalizer::to_vec(&real_claims).unwrap())
        .unwrap();
    let cross_role = SignedApprovalV1::from_cose_sign1(cross_role_bytes);
    assert_eq!(
        issuer
            .issue_approved(
                request(&invocation, &policy_decision, idempotency),
                &cross_role,
            )
            .unwrap_err(),
        CapabilityV2Error::UnknownApprovalKey
    );

    // Bit-flip in the signed envelope.
    let mut tampered_bytes = real.as_bytes().to_vec();
    let last = tampered_bytes.len() - 1;
    tampered_bytes[last] ^= 0x01;
    let tampered = SignedApprovalV1::from_cose_sign1(tampered_bytes);
    assert!(matches!(
        issuer
            .issue_approved(
                request(&invocation, &policy_decision, idempotency),
                &tampered,
            )
            .unwrap_err(),
        CapabilityV2Error::InvalidApprovalSignature | CapabilityV2Error::InvalidApprovalEnvelope
    ));
}

#[test]
fn temporal_rules_fail_closed() {
    let invocation = prepared("authorized input");
    let idempotency = Uuid::from_u128(16);
    let policy_decision = decision(&invocation, AutomationLevel::L3BoundedAuto, idempotency);

    // Expired approval: valid for 60 s, presented 120 s later.
    let short = approve_at(NOW + 10, &invocation, &policy_decision, 60);
    assert_eq!(
        issuer_at(NOW + 130)
            .issue_approved(request(&invocation, &policy_decision, idempotency), &short)
            .unwrap_err(),
        CapabilityV2Error::ApprovalExpired
    );

    // Future-dated approval.
    let future = approve_at(NOW + 300, &invocation, &policy_decision, 300);
    assert_eq!(
        issuer_at(NOW + 10)
            .issue_approved(request(&invocation, &policy_decision, idempotency), &future)
            .unwrap_err(),
        CapabilityV2Error::ApprovalFromFuture
    );

    // Approval predating the policy decision it claims to approve.
    let too_early = approve_at(NOW - 30, &invocation, &policy_decision, 300);
    assert_eq!(
        issuer_at(NOW + 10)
            .issue_approved(
                request(&invocation, &policy_decision, idempotency),
                &too_early,
            )
            .unwrap_err(),
        CapabilityV2Error::ApprovalMismatch("approved_at_unix")
    );

    // Out-of-range lifetime is rejected at signing time.
    assert_eq!(
        approve_invocation(
            &approver(),
            &FixedClock(NOW + 5),
            ApprovalGrantRequest {
                approver_subject_id: APPROVER,
                audience: AUDIENCE,
                venture_id: VENTURE,
                subject_id: SUBJECT,
                session_id: SESSION,
                policy_decision: &policy_decision,
                prepared_invocation: &invocation,
                ttl_seconds: APPROVAL_MAX_TTL_SECONDS + 1,
            },
        )
        .unwrap_err(),
        CapabilityV2Error::ApprovalLifetimeInvalid
    );

    // Stale policy decision: even with approval the extended window is capped.
    let late = approve_at(NOW + 550, &invocation, &policy_decision, 300);
    assert_eq!(
        issuer_at(NOW + APPROVAL_MAX_TTL_SECONDS + 60)
            .issue_approved(request(&invocation, &policy_decision, idempotency), &late)
            .unwrap_err(),
        CapabilityV2Error::PolicyAuthorizationStale
    );
}

#[test]
fn approval_reuse_across_tokens_is_denied_at_consumption() {
    let invocation = prepared("authorized input");
    let first_idempotency = Uuid::from_u128(17);
    let first_decision = decision(
        &invocation,
        AutomationLevel::L3BoundedAuto,
        first_idempotency,
    );
    let approval = approve_at(NOW + 5, &invocation, &first_decision, 300);
    let issuer = issuer_at(NOW + 10);

    let first_token = issuer
        .issue_approved(
            request(&invocation, &first_decision, first_idempotency),
            &approval,
        )
        .unwrap();
    // A second token minted from the same approval and decision (stateless
    // issuer) must still be stopped when the approval is consumed.
    let second_token = issuer
        .issue_approved(
            request(&invocation, &first_decision, first_idempotency),
            &approval,
        )
        .unwrap();

    let mut validator = validator_at(NOW + 20);
    consume(
        &mut validator,
        &first_token,
        &invocation,
        &first_decision,
        Some(&approval),
    )
    .unwrap();
    assert_eq!(
        consume(
            &mut validator,
            &second_token,
            &invocation,
            &first_decision,
            Some(&approval),
        )
        .unwrap_err(),
        CapabilityV2Error::ApprovalReused
    );
}

#[test]
fn evidence_where_none_is_required_fails_closed() {
    let invocation = prepared("plain input");
    let idempotency = Uuid::from_u128(18);
    let policy_decision = decision(&invocation, AutomationLevel::L1Draft, idempotency);
    assert!(!policy_decision.requires_approval());
    let approval = approve_at(NOW + 5, &invocation, &policy_decision, 300);
    let issuer = issuer_at(NOW + 10);

    assert_eq!(
        issuer
            .issue_approved(
                request(&invocation, &policy_decision, idempotency),
                &approval,
            )
            .unwrap_err(),
        CapabilityV2Error::UnexpectedApprovalEvidence
    );

    // A legitimate no-approval token presented WITH an approval object also
    // fails closed at consumption.
    let token = issuer
        .issue(request(&invocation, &policy_decision, idempotency))
        .unwrap();
    let mut validator = validator_at(NOW + 20);
    assert_eq!(
        consume(
            &mut validator,
            &token,
            &invocation,
            &policy_decision,
            Some(&approval),
        )
        .unwrap_err(),
        CapabilityV2Error::UnexpectedApprovalEvidence
    );
}

#[test]
fn approved_token_without_presented_object_fails_closed() {
    let invocation = prepared("authorized input");
    let idempotency = Uuid::from_u128(19);
    let policy_decision = decision(&invocation, AutomationLevel::L3BoundedAuto, idempotency);
    let approval = approve_at(NOW + 5, &invocation, &policy_decision, 300);
    let token = issuer_at(NOW + 10)
        .issue_approved(
            request(&invocation, &policy_decision, idempotency),
            &approval,
        )
        .unwrap();

    let mut validator = validator_at(NOW + 20);
    assert_eq!(
        consume(&mut validator, &token, &invocation, &policy_decision, None).unwrap_err(),
        CapabilityV2Error::ApprovalEvidenceMismatch
    );

    // And a validator without approval trust configured fails closed too.
    let trusted =
        TypedSigner::<AuthorityRole>::from_secret_bytes(AUTHORITY_ISSUER, AUTHORITY_SECRET)
            .unwrap();
    let mut authority_trust = RoleTrustStore::<AuthorityRole>::new();
    authority_trust
        .trust_signer(&trusted, KeyValidity::new(NOW - 60, NOW + 7_200).unwrap())
        .unwrap();
    let mut bare_validator = CapabilityValidatorV2::new(
        authority_trust,
        AUTHORITY_ISSUER,
        AUDIENCE,
        FixedClock(NOW + 20),
    )
    .unwrap();
    assert_eq!(
        bare_validator
            .authorize_and_consume_approved(
                &token,
                context(&invocation, &policy_decision),
                Some(&approval),
            )
            .unwrap_err(),
        CapabilityV2Error::ApprovalTrustUnavailable
    );
}

#[test]
fn durable_store_denies_replay_across_validator_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let invocation = prepared("durable input");
    let idempotency = Uuid::from_u128(21);
    let policy_decision = decision(&invocation, AutomationLevel::L3BoundedAuto, idempotency);
    let approval = approve_at(NOW + 5, &invocation, &policy_decision, 300);
    let token = issuer_at(NOW + 10)
        .issue_approved(
            request(&invocation, &policy_decision, idempotency),
            &approval,
        )
        .unwrap();

    // First "process": consumes token, idempotency key, and approval durably.
    let mut first = validator_at(NOW + 20)
        .with_authority_store(sovereign_authority::AuthorityStore::open(dir.path()).unwrap());
    consume(
        &mut first,
        &token,
        &invocation,
        &policy_decision,
        Some(&approval),
    )
    .unwrap();

    // Second "process" after a restart: fresh validator, empty in-memory
    // state, same store directory. Replay must still be denied.
    let mut second = validator_at(NOW + 25)
        .with_authority_store(sovereign_authority::AuthorityStore::open(dir.path()).unwrap());
    assert_eq!(
        consume(
            &mut second,
            &token,
            &invocation,
            &policy_decision,
            Some(&approval),
        )
        .unwrap_err(),
        CapabilityV2Error::Replay
    );

    // A different token minted from the same approval also fails after
    // restart: the approval id was durably consumed.
    let second_token = issuer_at(NOW + 10)
        .issue_approved(
            request(&invocation, &policy_decision, idempotency),
            &approval,
        )
        .unwrap();
    let mut third = validator_at(NOW + 30)
        .with_authority_store(sovereign_authority::AuthorityStore::open(dir.path()).unwrap());
    let error = consume(
        &mut third,
        &second_token,
        &invocation,
        &policy_decision,
        Some(&approval),
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            CapabilityV2Error::IdempotencyReplay | CapabilityV2Error::ApprovalReused
        ),
        "durable idempotency or approval consumption must deny: {error:?}"
    );
}

#[cfg(unix)]
#[test]
fn broken_authority_store_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let store = sovereign_authority::AuthorityStore::open(dir.path()).unwrap();
    // Break the store after opening: replace the tokens directory with a file.
    std::fs::remove_dir_all(dir.path().join("tokens")).unwrap();
    std::fs::write(dir.path().join("tokens"), b"broken").unwrap();

    let invocation = prepared("plain input");
    let idempotency = Uuid::from_u128(22);
    let policy_decision = decision(&invocation, AutomationLevel::L1Draft, idempotency);
    let token = issuer_at(NOW + 5)
        .issue(request(&invocation, &policy_decision, idempotency))
        .unwrap();
    let mut validator = validator_at(NOW + 10).with_authority_store(store);
    assert_eq!(
        consume(&mut validator, &token, &invocation, &policy_decision, None).unwrap_err(),
        CapabilityV2Error::AuthorityStoreUnavailable
    );
}
