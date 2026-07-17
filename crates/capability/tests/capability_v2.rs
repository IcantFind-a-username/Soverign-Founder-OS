use chrono::{DateTime, Duration, Utc};
use sovereign_artifact::{
    AdmissionLimits, ArtifactBackend, ArtifactVerificationIntent, ArtifactVerifier, Digest,
    OperationSelector, PreparedInvocation, RawResourceGrant, RiskClass,
    TrustedClock as ArtifactClock, CORE_WASM_ENTRYPOINT, MANIFEST_PROTOCOL_VERSION,
};
use sovereign_capability::v2::{
    policy_decision_digest, ApprovalEvidenceV2, CapabilityClaimsV2, CapabilityIssuerV2,
    CapabilityTokenV2, CapabilityV2Error, CapabilityV2IssueOptions, CapabilityV2IssueRequest,
    CapabilityV2ValidationContext, CapabilityValidatorV2, ToolScopeV2, TrustedClock,
    CAPABILITY_V2_CANONICALIZATION, CAPABILITY_V2_MAX_TOKEN_BYTES, CAPABILITY_V2_TYPE,
    CAPABILITY_V2_VERSION,
};
use sovereign_capability::{CapabilityIssuer, IssueOptions};
use sovereign_contracts::{ActionRequest, AutomationLevel, DataClass};
use sovereign_identity::{AuthorityRole, KeyValidity, PublisherRole, RoleTrustStore, TypedSigner};
use sovereign_policy::{AuthenticatedPolicyContextV2, PolicyAuthorizationV2, PolicyEngine};
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;
const ISSUER: &str = "authority.local";
const AUDIENCE: &str = "sovereign-runtime";
const VENTURE: &str = "venture-alpha";
const SUBJECT: &str = "founder-session-subject";
const PUBLISHER: &str = "publisher.local";
const RESOURCE: &str = "draft:alpha";
const AUTHORITY_SECRET: [u8; 32] = [0x41; 32];
const PUBLISHER_SECRET: [u8; 32] = [0x50; 32];
const COMPONENT: &[u8] = b"\0asm\x01\0\0\0capability-v2-fixture";

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

fn prepared(content: &str) -> PreparedInvocation {
    let publisher =
        TypedSigner::<PublisherRole>::from_secret_bytes(PUBLISHER, PUBLISHER_SECRET).unwrap();
    let publisher_key_id = Digest::from_bytes(*publisher.key_id());
    let manifest = serde_json::json!({
        "protocol_version": MANIFEST_PROTOCOL_VERSION,
        "publisher_issuer": PUBLISHER,
        "publisher_key_id": publisher_key_id,
        "component_digest": Digest::of_bytes(COMPONENT),
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
            "input_limits": {
                "max_bytes": 4096,
                "max_depth": 8
            },
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
    let canonical_manifest = serde_json_canonicalizer::to_vec(&manifest).unwrap();
    let signed_manifest = publisher.sign_cose(&canonical_manifest).unwrap();
    let mut publishers = RoleTrustStore::<PublisherRole>::new();
    publishers
        .trust_signer(&publisher, KeyValidity::new(NOW - 60, NOW + 3_600).unwrap())
        .unwrap();
    let intent = ArtifactVerificationIntent::new(
        PUBLISHER,
        Digest::of_bytes(&signed_manifest),
        Digest::of_bytes(COMPONENT),
    )
    .unwrap();
    let artifact =
        ArtifactVerifier::with_clock(&publishers, AdmissionLimits::default(), FixedClock(NOW))
            .verify(&intent, &signed_manifest, COMPONENT)
            .unwrap();
    let selector = OperationSelector::new("document.transform", "1.0.0", "render").unwrap();
    let input = serde_json::to_vec(&serde_json::json!({
        "content": content,
        "resource": RESOURCE
    }))
    .unwrap();
    PreparedInvocation::prepare(
        &artifact,
        &selector,
        &input,
        vec![RawResourceGrant::new("primary", RESOURCE)],
    )
    .unwrap()
}

fn authorization(
    prepared: &PreparedInvocation,
    automation_level: AutomationLevel,
) -> PolicyAuthorizationV2 {
    PolicyEngine::with_clock(FixedClock(NOW))
        .evaluate_prepared(
            prepared,
            AuthenticatedPolicyContextV2::new(
                AUDIENCE,
                VENTURE,
                SUBJECT,
                Uuid::from_u128(1),
                DataClass::Green,
                automation_level,
                Uuid::from_u128(2),
            )
            .unwrap(),
        )
        .unwrap()
}

fn decision(prepared: &PreparedInvocation) -> PolicyAuthorizationV2 {
    authorization(prepared, AutomationLevel::L1Draft)
}

fn authority_signer() -> TypedSigner<AuthorityRole> {
    TypedSigner::<AuthorityRole>::from_secret_bytes(ISSUER, AUTHORITY_SECRET).unwrap()
}

fn authority(
    validator_now: i64,
) -> (
    CapabilityIssuerV2<FixedClock>,
    CapabilityValidatorV2<FixedClock>,
) {
    let trust_signer = authority_signer();
    let mut trust_store = RoleTrustStore::<AuthorityRole>::new();
    trust_store
        .trust_signer(
            &trust_signer,
            KeyValidity::new(NOW - 60, NOW + 3_600).unwrap(),
        )
        .unwrap();
    let issuer = CapabilityIssuerV2::new(authority_signer(), AUDIENCE, FixedClock(NOW)).unwrap();
    let validator =
        CapabilityValidatorV2::new(trust_store, ISSUER, AUDIENCE, FixedClock(validator_now))
            .unwrap();
    (issuer, validator)
}

fn validator_with_trust(
    validity: Option<KeyValidity>,
    trusted_issuer: &str,
    revoked: bool,
) -> CapabilityValidatorV2<FixedClock> {
    let signer = authority_signer();
    let mut trust_store = RoleTrustStore::<AuthorityRole>::new();
    if let Some(validity) = validity {
        let key_id = trust_store
            .add_key(trusted_issuer, signer.public_key_bytes(), validity)
            .unwrap();
        if revoked {
            trust_store.revoke(&key_id).unwrap();
        }
    }
    CapabilityValidatorV2::new(trust_store, ISSUER, AUDIENCE, FixedClock(NOW)).unwrap()
}

fn issue(
    issuer: &CapabilityIssuerV2<FixedClock>,
    prepared: &PreparedInvocation,
    decision: &PolicyAuthorizationV2,
    _session_id: Uuid,
    _idempotency_key: Uuid,
) -> CapabilityTokenV2 {
    issuer
        .issue(CapabilityV2IssueRequest {
            venture_id: VENTURE,
            subject_id: SUBJECT,
            session_id: decision.session_id(),
            policy_decision: decision,
            prepared_invocation: prepared,
            options: CapabilityV2IssueOptions {
                ttl: Duration::seconds(60),
                idempotency_key: decision.idempotency_key(),
            },
        })
        .unwrap()
}

fn context<'a>(
    prepared: &'a PreparedInvocation,
    decision: &'a PolicyAuthorizationV2,
    _session_id: Uuid,
) -> CapabilityV2ValidationContext<'a> {
    CapabilityV2ValidationContext {
        venture_id: VENTURE,
        subject_id: SUBJECT,
        session_id: decision.session_id(),
        policy_decision: decision,
        prepared_invocation: prepared,
    }
}

fn claims(
    prepared: &PreparedInvocation,
    decision: &PolicyAuthorizationV2,
    _session_id: Uuid,
) -> CapabilityClaimsV2 {
    let signer = authority_signer();
    CapabilityClaimsV2 {
        typ: CAPABILITY_V2_TYPE.into(),
        version: CAPABILITY_V2_VERSION,
        issuer: ISSUER.into(),
        issuer_key_id: Digest::from_bytes(*signer.key_id()),
        audience: AUDIENCE.into(),
        token_id: Uuid::new_v4(),
        venture_id: VENTURE.into(),
        subject_id: SUBJECT.into(),
        session_id: decision.session_id(),
        tool: ToolScopeV2 {
            tool_id: prepared.operation().tool_id().into(),
            tool_version: prepared.operation().tool_version().into(),
            operation: prepared.operation().operation_id().into(),
        },
        component_digest: prepared.artifact().component_digest(),
        manifest_digest: prepared.artifact().manifest_digest(),
        canonical_input_digest: prepared.input_digest(),
        resource_bindings_digest: prepared.bindings_digest(),
        canonicalization_profile: CAPABILITY_V2_CANONICALIZATION.into(),
        primary_resource: prepared.primary_resource().unwrap().into(),
        policy_decision_id: decision.decision_id(),
        policy_decision_digest: policy_decision_digest(decision).unwrap(),
        approval_evidence: None,
        idempotency_key: decision.idempotency_key(),
        issued_at_unix: NOW,
        expires_at_unix: NOW + 60,
        max_uses: 1,
        risk_class: RiskClass::PureCompute,
        backend: ArtifactBackend::CoreWasm,
    }
}

fn sign_claims(claims: &CapabilityClaimsV2) -> CapabilityTokenV2 {
    let payload = serde_json_canonicalizer::to_vec(claims).unwrap();
    CapabilityTokenV2::from_cose_sign1(authority_signer().sign_cose(&payload).unwrap())
}

fn sign_value(value: &serde_json::Value) -> CapabilityTokenV2 {
    let payload = serde_json_canonicalizer::to_vec(value).unwrap();
    CapabilityTokenV2::from_cose_sign1(authority_signer().sign_cose(&payload).unwrap())
}

#[test]
fn issues_and_consumes_one_exact_verified_pure_compute_invocation() {
    let (issuer, mut validator) = authority(NOW);
    let prepared = prepared("first input");
    let decision = decision(&prepared);
    let session_id = Uuid::new_v4();
    let token = issue(&issuer, &prepared, &decision, session_id, Uuid::new_v4());

    let authorized = validator
        .authorize_and_consume(&token, context(&prepared, &decision, session_id))
        .unwrap();
    assert_eq!(authorized.claims().subject_id, SUBJECT);
    assert_eq!(
        authorized.claims().component_digest,
        prepared.artifact().component_digest()
    );
    assert_eq!(authorized.claims().approval_evidence, None);
    assert_eq!(authorized.claims().max_uses, 1);
}

#[test]
fn rejects_cose_signature_tampering() {
    let (issuer, mut validator) = authority(NOW);
    let prepared = prepared("first input");
    let decision = decision(&prepared);
    let session_id = Uuid::new_v4();
    let token = issue(&issuer, &prepared, &decision, session_id, Uuid::new_v4());
    let mut tampered = token.into_bytes();
    *tampered.last_mut().unwrap() ^= 1;
    let tampered = CapabilityTokenV2::from_cose_sign1(tampered);

    assert!(matches!(
        validator.authorize_and_consume(&tampered, context(&prepared, &decision, session_id)),
        Err(CapabilityV2Error::InvalidAuthoritySignature)
    ));
}

#[test]
fn rejects_oversized_token_before_cose_parsing() {
    let prepared = prepared("first input");
    let decision = decision(&prepared);
    let token = CapabilityTokenV2::from_cose_sign1(vec![0; CAPABILITY_V2_MAX_TOKEN_BYTES + 1]);
    let (_, mut validator) = authority(NOW);

    assert!(matches!(
        validator.authorize_and_consume(&token, context(&prepared, &decision, Uuid::new_v4())),
        Err(CapabilityV2Error::TokenTooLarge)
    ));
}

#[test]
fn rejects_expired_token_using_validator_owned_clock() {
    let (issuer, mut validator) = authority(NOW + 60);
    let prepared = prepared("first input");
    let decision = decision(&prepared);
    let session_id = Uuid::new_v4();
    let token = issue(&issuer, &prepared, &decision, session_id, Uuid::new_v4());

    assert!(matches!(
        validator.authorize_and_consume(&token, context(&prepared, &decision, session_id)),
        Err(CapabilityV2Error::Expired)
    ));
}

#[test]
fn rejects_token_replay_before_a_second_execution() {
    let (issuer, mut validator) = authority(NOW);
    let prepared = prepared("first input");
    let decision = decision(&prepared);
    let session_id = Uuid::new_v4();
    let token = issue(&issuer, &prepared, &decision, session_id, Uuid::new_v4());

    validator
        .authorize_and_consume(&token, context(&prepared, &decision, session_id))
        .unwrap();
    assert!(matches!(
        validator.authorize_and_consume(&token, context(&prepared, &decision, session_id)),
        Err(CapabilityV2Error::Replay)
    ));
}

#[test]
fn rejects_idempotency_key_reuse_for_substituted_input() {
    let (issuer, mut validator) = authority(NOW);
    let first = prepared("first input");
    let second = prepared("substituted input");
    let first_decision = decision(&first);
    let second_decision = decision(&second);
    let session_id = Uuid::new_v4();
    let idempotency_key = Uuid::new_v4();
    let first_token = issue(
        &issuer,
        &first,
        &first_decision,
        session_id,
        idempotency_key,
    );
    let second_token = issue(
        &issuer,
        &second,
        &second_decision,
        session_id,
        idempotency_key,
    );

    validator
        .authorize_and_consume(&first_token, context(&first, &first_decision, session_id))
        .unwrap();
    assert!(matches!(
        validator.authorize_and_consume(
            &second_token,
            context(&second, &second_decision, session_id)
        ),
        Err(CapabilityV2Error::IdempotencyConflict)
    ));
}

#[test]
fn rejects_wrong_audience_and_session() {
    let (issuer, _) = authority(NOW);
    let prepared = prepared("first input");
    let decision = decision(&prepared);
    let session_id = Uuid::new_v4();
    let token = issue(&issuer, &prepared, &decision, session_id, Uuid::new_v4());

    let signer = authority_signer();
    let mut trust_store = RoleTrustStore::<AuthorityRole>::new();
    trust_store
        .trust_signer(&signer, KeyValidity::new(NOW - 60, NOW + 3_600).unwrap())
        .unwrap();
    let mut wrong_audience =
        CapabilityValidatorV2::new(trust_store, ISSUER, "different-runtime", FixedClock(NOW))
            .unwrap();
    assert!(matches!(
        wrong_audience.authorize_and_consume(&token, context(&prepared, &decision, session_id)),
        Err(CapabilityV2Error::AudienceMismatch)
    ));

    let (_, mut validator) = authority(NOW);
    assert!(matches!(
        validator.authorize_and_consume(
            &token,
            CapabilityV2ValidationContext {
                venture_id: VENTURE,
                subject_id: SUBJECT,
                session_id: Uuid::new_v4(),
                policy_decision: &decision,
                prepared_invocation: &prepared,
            }
        ),
        Err(CapabilityV2Error::SessionMismatch)
    ));
}

#[test]
fn issuance_fails_closed_when_approval_is_required() {
    let (issuer, _) = authority(NOW);
    let prepared = prepared("first input");
    let decision = authorization(&prepared, AutomationLevel::L2ApproveExecute);

    let result = issuer.issue(CapabilityV2IssueRequest {
        venture_id: VENTURE,
        subject_id: SUBJECT,
        session_id: decision.session_id(),
        policy_decision: &decision,
        prepared_invocation: &prepared,
        options: CapabilityV2IssueOptions {
            ttl: Duration::seconds(60),
            idempotency_key: decision.idempotency_key(),
        },
    });
    assert!(matches!(
        result,
        Err(CapabilityV2Error::ApprovalEvidenceUnavailable)
    ));
}

#[test]
fn rejects_invocation_substitution_after_issuance() {
    let (issuer, mut validator) = authority(NOW);
    let original = prepared("first input");
    let substituted = prepared("attacker input");
    let decision = decision(&original);
    let session_id = Uuid::new_v4();
    let token = issue(&issuer, &original, &decision, session_id, Uuid::new_v4());

    assert!(matches!(
        validator.authorize_and_consume(&token, context(&substituted, &decision, session_id)),
        Err(CapabilityV2Error::InvocationMismatch(
            "canonical_input_digest"
        ))
    ));
}

#[test]
fn maps_authority_trust_failures_to_stable_classes() {
    let (issuer, _) = authority(NOW);
    let prepared = prepared("first input");
    let decision = decision(&prepared);
    let session_id = Uuid::new_v4();
    let token = issue(&issuer, &prepared, &decision, session_id, Uuid::new_v4());

    let cases = [
        (
            validator_with_trust(None, ISSUER, false),
            CapabilityV2Error::UnknownAuthorityKey,
        ),
        (
            validator_with_trust(
                Some(KeyValidity::new(NOW - 60, NOW + 60).unwrap()),
                ISSUER,
                true,
            ),
            CapabilityV2Error::AuthorityKeyRevoked,
        ),
        (
            validator_with_trust(
                Some(KeyValidity::new(NOW + 1, NOW + 60).unwrap()),
                ISSUER,
                false,
            ),
            CapabilityV2Error::AuthorityKeyNotYetValid,
        ),
        (
            validator_with_trust(
                Some(KeyValidity::new(NOW - 60, NOW).unwrap()),
                ISSUER,
                false,
            ),
            CapabilityV2Error::AuthorityKeyExpired,
        ),
        (
            validator_with_trust(
                Some(KeyValidity::new(NOW - 60, NOW + 60).unwrap()),
                "different-authority.local",
                false,
            ),
            CapabilityV2Error::AuthorityIssuerMismatch,
        ),
    ];

    for (mut validator, expected) in cases {
        let actual = validator
            .authorize_and_consume(&token, context(&prepared, &decision, session_id))
            .unwrap_err();
        assert_eq!(actual, expected);
    }
}

#[test]
fn strict_claims_require_explicit_null_approval_and_reject_unknown_fields() {
    let prepared = prepared("first input");
    let decision = decision(&prepared);
    let session_id = Uuid::new_v4();
    let base = claims(&prepared, &decision, session_id);

    let mut missing = serde_json::to_value(&base).unwrap();
    missing.as_object_mut().unwrap().remove("approval_evidence");
    let missing = sign_value(&missing);
    let (_, mut validator) = authority(NOW);
    assert!(matches!(
        validator.authorize_and_consume(&missing, context(&prepared, &decision, session_id)),
        Err(CapabilityV2Error::InvalidClaims)
    ));

    let mut unknown = serde_json::to_value(&base).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("agent_says_ok".into(), serde_json::Value::Bool(true));
    let unknown = sign_value(&unknown);
    let (_, mut validator) = authority(NOW);
    assert!(matches!(
        validator.authorize_and_consume(&unknown, context(&prepared, &decision, session_id)),
        Err(CapabilityV2Error::InvalidClaims)
    ));
}

#[test]
fn rejects_self_supplied_approval_evidence_and_backend_downgrade() {
    let prepared = prepared("first input");
    let decision = decision(&prepared);
    let session_id = Uuid::new_v4();

    let mut with_approval = claims(&prepared, &decision, session_id);
    with_approval.approval_evidence = Some(ApprovalEvidenceV2 {
        approval_id: Uuid::new_v4(),
        approver_subject_id: "untrusted-self-approval".into(),
        approved_at_unix: NOW,
    });
    let token = sign_claims(&with_approval);
    let (_, mut validator) = authority(NOW);
    // RFC 0003: evidence on a decision that does not require approval is
    // rejected as unexpected, whether or not an approval object is presented.
    assert!(matches!(
        validator.authorize_and_consume(&token, context(&prepared, &decision, session_id)),
        Err(CapabilityV2Error::UnexpectedApprovalEvidence)
    ));

    let mut downgraded = claims(&prepared, &decision, session_id);
    downgraded.backend = ArtifactBackend::ComponentWasm;
    let token = sign_claims(&downgraded);
    let (_, mut validator) = authority(NOW);
    assert!(matches!(
        validator.authorize_and_consume(&token, context(&prepared, &decision, session_id)),
        Err(CapabilityV2Error::BackendDowngradeDenied)
    ));
}

#[test]
fn v1_json_token_is_not_a_v2_cose_token() {
    let prepared = prepared("first input");
    let v2_decision = decision(&prepared);
    let decision = PolicyEngine::new().evaluate(ActionRequest {
        actor_id: SUBJECT.into(),
        venture_id: VENTURE.into(),
        tool: prepared.operation().tool_id().into(),
        operation: prepared.operation().operation_id().into(),
        resource: prepared.primary_resource().unwrap().into(),
        data_class: DataClass::Green,
        automation_level: AutomationLevel::L1Draft,
    });
    let v1_issuer = CapabilityIssuer::new();
    let v1_token = v1_issuer
        .issue(&decision, IssueOptions::default(), false)
        .unwrap();
    let untrusted_v2 = CapabilityTokenV2::from_cose_sign1(serde_json::to_vec(&v1_token).unwrap());
    let (_, mut validator) = authority(NOW);

    assert!(matches!(
        validator.authorize_and_consume(
            &untrusted_v2,
            context(&prepared, &v2_decision, Uuid::new_v4())
        ),
        Err(CapabilityV2Error::InvalidCapabilityEnvelope)
    ));
}
