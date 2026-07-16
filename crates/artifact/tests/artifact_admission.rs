use serde_json::{json, Value};
use sovereign_artifact::{
    AdmissionLimits, ArtifactError, ArtifactVerificationIntent, ArtifactVerifier, Digest,
    OperationSelector, PreparedInvocation, RawResourceGrant, TrustedClock,
    HARD_MAX_COMPONENT_BYTES, HARD_MAX_MANIFEST_PAYLOAD_BYTES, HARD_MAX_SIGNED_MANIFEST_BYTES,
    IJSON_SAFE_INTEGER_MAX, IJSON_SAFE_INTEGER_MIN,
};
use sovereign_identity::{KeyValidity, PublisherRole, RoleTrustStore, TypedSigner};

const ISSUER: &str = "publisher.example";
const NOW: i64 = 1_000;

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl TrustedClock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.0
    }
}

fn component_a() -> Vec<u8> {
    b"\0asm\x01\0\0\0phase-b-a".to_vec()
}

fn component_b() -> Vec<u8> {
    b"\0asm\x01\0\0\0phase-b-b".to_vec()
}

fn publisher() -> (TypedSigner<PublisherRole>, RoleTrustStore<PublisherRole>) {
    let signer = TypedSigner::<PublisherRole>::generate(ISSUER).unwrap();
    let mut trust = RoleTrustStore::<PublisherRole>::new();
    trust
        .trust_signer(&signer, KeyValidity::new(0, 10_000).unwrap())
        .unwrap();
    (signer, trust)
}

fn manifest(component: &[u8], signer: &TypedSigner<PublisherRole>) -> Value {
    json!({
        "protocol_version": 1,
        "publisher_issuer": signer.issuer(),
        "publisher_key_id": hex::encode(signer.key_id()),
        "component_digest": Digest::of_bytes(component).as_hex(),
        "backend": "core_wasm",
        "risk_class": "pure_compute",
        "abi": "sovereign_core_wasm_v1",
        "entrypoint": "sovereign_run",
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
                    "payload": {
                        "type": "object",
                        "properties": {
                            "message": {"type": "string", "max_utf8_bytes": 256},
                            "priority": {"type": "integer", "minimum": 0, "maximum": 10}
                        },
                        "required": ["message", "priority"],
                        "max_properties": 2
                    },
                    "recipient": {"type": "string", "max_utf8_bytes": 256},
                    "tags": {
                        "type": "array",
                        "items": {"type": "string", "max_utf8_bytes": 64},
                        "max_items": 8
                    }
                },
                "required": ["payload", "recipient"],
                "max_properties": 3
            },
            "resource_bindings": [{
                "binding_id": "recipient",
                "json_pointer": "/recipient",
                "normalization": "exact_utf8_v1",
                "primary": true
            }]
        }]
    })
}

fn sign_value(value: &Value, signer: &TypedSigner<PublisherRole>) -> Vec<u8> {
    let canonical = serde_json_canonicalizer::to_vec(value).unwrap();
    signer.sign_cose(&canonical).unwrap()
}

fn selector() -> OperationSelector {
    OperationSelector::new("document.transform", "1.0.0", "render").unwrap()
}

fn intent(signed: &[u8], component: &[u8]) -> ArtifactVerificationIntent {
    ArtifactVerificationIntent::new(
        ISSUER,
        Digest::of_bytes(signed),
        Digest::of_bytes(component),
    )
    .unwrap()
}

fn verify_with_intent(
    trust: &RoleTrustStore<PublisherRole>,
    intent: &ArtifactVerificationIntent,
    signed: &[u8],
    component: &[u8],
) -> Result<sovereign_artifact::VerifiedArtifact, ArtifactError> {
    ArtifactVerifier::with_clock(trust, AdmissionLimits::default(), FixedClock(NOW))
        .verify(intent, signed, component)
}

fn verify_artifact(
    trust: &RoleTrustStore<PublisherRole>,
    signed: &[u8],
    component: &[u8],
) -> Result<sovereign_artifact::VerifiedArtifact, ArtifactError> {
    verify_with_intent(trust, &intent(signed, component), signed, component)
}

#[test]
fn immutable_intent_rejects_same_publisher_manifest_and_component_substitution() {
    let (signer, trust) = publisher();
    let first_component = component_a();
    let signed = sign_value(&manifest(&first_component, &signer), &signer);
    let pinned_intent = intent(&signed, &first_component);
    let first = verify_with_intent(&trust, &pinned_intent, &signed, &first_component).unwrap();

    let substituted_component = component_b();
    assert!(matches!(
        verify_with_intent(&trust, &pinned_intent, &signed, &substituted_component),
        Err(ArtifactError::ComponentDigestMismatch { .. })
    ));

    let mut substituted_manifest = manifest(&first_component, &signer);
    substituted_manifest["operations"][0]["selector"]["operation_id"] =
        Value::String("other".into());
    let substituted_signed = sign_value(&substituted_manifest, &signer);
    assert!(matches!(
        verify_with_intent(
            &trust,
            &pinned_intent,
            &substituted_signed,
            &first_component
        ),
        Err(ArtifactError::SignedEnvelopeDigestMismatch { .. })
    ));

    assert_eq!(first.component_digest(), pinned_intent.component_digest());
}

#[test]
fn verification_limits_are_checked_and_cannot_exceed_hard_maxima() {
    let limits = AdmissionLimits::new(16 * 1024, 8 * 1024, 64 * 1024).unwrap();
    assert_eq!(limits.max_signed_manifest_bytes(), 16 * 1024);
    assert_eq!(limits.max_manifest_payload_bytes(), 8 * 1024);
    assert_eq!(limits.max_component_bytes(), 64 * 1024);

    assert_eq!(
        AdmissionLimits::new(0, 1, 1),
        Err(ArtifactError::InvalidVerificationLimits)
    );
    assert_eq!(
        AdmissionLimits::new(1, 0, 1),
        Err(ArtifactError::InvalidVerificationLimits)
    );
    assert_eq!(
        AdmissionLimits::new(1, 1, 0),
        Err(ArtifactError::InvalidVerificationLimits)
    );
    assert_eq!(
        AdmissionLimits::new(HARD_MAX_SIGNED_MANIFEST_BYTES + 1, 1, 1),
        Err(ArtifactError::InvalidVerificationLimits)
    );
    assert_eq!(
        AdmissionLimits::new(
            HARD_MAX_SIGNED_MANIFEST_BYTES,
            HARD_MAX_MANIFEST_PAYLOAD_BYTES + 1,
            1,
        ),
        Err(ArtifactError::InvalidVerificationLimits)
    );
    assert_eq!(
        AdmissionLimits::new(2, 3, 1),
        Err(ArtifactError::InvalidVerificationLimits)
    );
    assert_eq!(
        AdmissionLimits::new(1, 1, HARD_MAX_COMPONENT_BYTES + 1),
        Err(ArtifactError::InvalidVerificationLimits)
    );
}

#[test]
fn invalid_verification_issuer_is_rejected_before_verification() {
    assert_eq!(
        ArtifactVerificationIntent::new(
            " publisher.example",
            Digest::of_bytes(b"envelope"),
            Digest::of_bytes(b"component"),
        ),
        Err(ArtifactError::InvalidVerificationIntent)
    );
}

#[test]
fn key_order_is_equivalent_but_input_substitution_changes_commitments() {
    let (signer, trust) = publisher();
    let component = component_a();
    let signed = sign_value(&manifest(&component, &signer), &signer);
    let artifact = verify_artifact(&trust, &signed, &component).unwrap();

    let first = PreparedInvocation::prepare(
        &artifact,
        &selector(),
        br#"{"recipient":"customer:42","payload":{"message":"hello","priority":1},"tags":["a","b"]}"#,
        vec![RawResourceGrant::new("recipient", "customer:42")],
    )
    .unwrap();
    let reordered = PreparedInvocation::prepare(
        &artifact,
        &selector(),
        br#"{"tags":["a","b"],"payload":{"priority":1,"message":"hello"},"recipient":"customer:42"}"#,
        vec![RawResourceGrant::new("recipient", "customer:42")],
    )
    .unwrap();
    assert_eq!(first.canonical_input(), reordered.canonical_input());
    assert_eq!(first.input_digest(), reordered.input_digest());
    assert_eq!(first.bindings_digest(), reordered.bindings_digest());

    let substituted = PreparedInvocation::prepare(
        &artifact,
        &selector(),
        br#"{"recipient":"customer:admin","payload":{"message":"hello","priority":1}}"#,
        vec![RawResourceGrant::new("recipient", "customer:admin")],
    )
    .unwrap();
    assert_eq!(
        substituted.ensure_commitments(first.input_digest(), first.bindings_digest()),
        Err(ArtifactError::InputDigestMismatch)
    );
    assert_ne!(first.bindings_digest(), substituted.bindings_digest());
    assert_eq!(first.primary_resource(), Some("customer:42"));
}

#[test]
fn resource_substitution_and_extra_grants_fail_closed() {
    let (signer, trust) = publisher();
    let component = component_a();
    let artifact = verify_artifact(
        &trust,
        &sign_value(&manifest(&component, &signer), &signer),
        &component,
    )
    .unwrap();
    let input = br#"{"recipient":"customer:42","payload":{"message":"hello","priority":1}}"#;

    assert_eq!(
        PreparedInvocation::prepare(
            &artifact,
            &selector(),
            input,
            vec![RawResourceGrant::new("recipient", "customer:admin")],
        )
        .unwrap_err(),
        ArtifactError::ResourceGrantMismatch("recipient".into())
    );
    assert_eq!(
        PreparedInvocation::prepare(
            &artifact,
            &selector(),
            input,
            vec![
                RawResourceGrant::new("recipient", "customer:42"),
                RawResourceGrant::new("undeclared", "secret"),
            ],
        )
        .unwrap_err(),
        ArtifactError::UnexpectedResourceGrant("undeclared".into())
    );
}

#[test]
fn strict_manifest_and_input_reject_unknown_and_duplicate_fields() {
    let (signer, trust) = publisher();
    let component = component_a();

    let mut unknown_manifest = manifest(&component, &signer);
    unknown_manifest["unexpected"] = Value::Bool(true);
    assert!(matches!(
        verify_artifact(&trust, &sign_value(&unknown_manifest, &signer), &component),
        Err(ArtifactError::InvalidManifest(_))
    ));

    let canonical = serde_json_canonicalizer::to_string(&manifest(&component, &signer)).unwrap();
    let duplicate = canonical.replacen('{', "{\"protocol_version\":1,", 1);
    let duplicate_signed = signer.sign_cose(duplicate.as_bytes()).unwrap();
    assert!(matches!(
        verify_artifact(&trust, &duplicate_signed, &component),
        Err(ArtifactError::InvalidManifest(_))
    ));

    let artifact = verify_artifact(
        &trust,
        &sign_value(&manifest(&component, &signer), &signer),
        &component,
    )
    .unwrap();
    assert!(matches!(
        PreparedInvocation::prepare(
            &artifact,
            &selector(),
            br#"{"recipient":"customer:42","payload":{"message":"hello","priority":1},"unknown":true}"#,
            vec![RawResourceGrant::new("recipient", "customer:42")],
        ),
        Err(ArtifactError::InputSchemaMismatch { .. })
    ));
    assert_eq!(
        PreparedInvocation::prepare(
            &artifact,
            &selector(),
            br#"{"recipient":"customer:42","payload":{"message":"hello","message":"evil","priority":1}}"#,
            vec![RawResourceGrant::new("recipient", "customer:42")],
        )
        .unwrap_err(),
        ArtifactError::DuplicateInputKey("message".into())
    );
}

#[test]
fn integer_schema_and_inputs_are_limited_to_ijson_safe_range() {
    let (signer, trust) = publisher();
    let component = component_a();
    let mut safe_manifest = manifest(&component, &signer);
    let priority = &mut safe_manifest["operations"][0]["input_schema"]["properties"]["payload"]
        ["properties"]["priority"];
    priority["minimum"] = json!(IJSON_SAFE_INTEGER_MIN);
    priority["maximum"] = json!(IJSON_SAFE_INTEGER_MAX);
    let signed = sign_value(&safe_manifest, &signer);
    let artifact = verify_artifact(&trust, &signed, &component).unwrap();

    for value in [IJSON_SAFE_INTEGER_MIN, IJSON_SAFE_INTEGER_MAX] {
        let input = serde_json::to_vec(&json!({
            "recipient": "customer:42",
            "payload": {"message": "safe", "priority": value}
        }))
        .unwrap();
        PreparedInvocation::prepare(
            &artifact,
            &selector(),
            &input,
            vec![RawResourceGrant::new("recipient", "customer:42")],
        )
        .unwrap();
    }

    for value in [IJSON_SAFE_INTEGER_MIN - 1, IJSON_SAFE_INTEGER_MAX + 1] {
        let input = serde_json::to_vec(&json!({
            "recipient": "customer:42",
            "payload": {"message": "unsafe", "priority": value}
        }))
        .unwrap();
        assert!(matches!(
            PreparedInvocation::prepare(
                &artifact,
                &selector(),
                &input,
                vec![RawResourceGrant::new("recipient", "customer:42")],
            ),
            Err(ArtifactError::InputSchemaMismatch { .. })
        ));
    }

    for (bound, unsafe_value) in [
        ("minimum", IJSON_SAFE_INTEGER_MIN - 1),
        ("minimum", IJSON_SAFE_INTEGER_MAX + 1),
        ("maximum", IJSON_SAFE_INTEGER_MIN - 1),
        ("maximum", IJSON_SAFE_INTEGER_MAX + 1),
    ] {
        let mut invalid_manifest = manifest(&component, &signer);
        invalid_manifest["operations"][0]["input_schema"]["properties"]["payload"]["properties"]
            ["priority"][bound] = json!(unsafe_value);
        assert!(matches!(
            verify_artifact(&trust, &sign_value(&invalid_manifest, &signer), &component,),
            Err(ArtifactError::InvalidInputSchema(_))
        ));
    }
}

#[test]
fn protocol_risk_backend_and_host_capabilities_are_not_downgraded() {
    let (signer, trust) = publisher();
    let component = component_a();
    for (field, replacement, expected) in [
        (
            "protocol_version",
            json!(2),
            ArtifactError::UnsupportedProtocolVersion(2),
        ),
        (
            "risk_class",
            json!("low_risk_effectful"),
            ArtifactError::UnsupportedRiskClass,
        ),
        (
            "backend",
            json!("component_wasm"),
            ArtifactError::UnsupportedBackend,
        ),
    ] {
        let mut value = manifest(&component, &signer);
        value[field] = replacement;
        assert_eq!(
            verify_artifact(&trust, &sign_value(&value, &signer), &component).unwrap_err(),
            expected
        );
    }

    let mut value = manifest(&component, &signer);
    value["requested_host_capabilities"] = json!(["filesystem.read"]);
    assert_eq!(
        verify_artifact(&trust, &sign_value(&value, &signer), &component).unwrap_err(),
        ArtifactError::HostCapabilitiesForbidden
    );
}

#[test]
fn verified_artifact_and_prepared_input_own_the_verified_bytes() {
    let (signer, trust) = publisher();
    let mut component = component_a();
    let expected_component = component.clone();
    let signed = sign_value(&manifest(&component, &signer), &signer);
    let artifact = verify_artifact(&trust, &signed, &component).unwrap();
    component.fill(0xff);
    assert_eq!(artifact.bytes(), expected_component);
    assert_eq!(
        artifact.component_digest(),
        Digest::of_bytes(&expected_component)
    );

    let mut raw =
        br#"{"recipient":"customer:42","payload":{"message":"hello","priority":1}}"#.to_vec();
    let invocation = PreparedInvocation::prepare(
        &artifact,
        &selector(),
        &raw,
        vec![RawResourceGrant::new("recipient", "customer:42")],
    )
    .unwrap();
    let canonical = invocation.canonical_input().to_vec();
    raw.fill(b'x');
    assert_eq!(invocation.canonical_input(), canonical);
    assert_eq!(invocation.artifact().bytes(), expected_component);
}

#[test]
fn debug_output_redacts_artifact_input_and_resource_secrets() {
    let (signer, trust) = publisher();
    let component = component_a();
    let signed = sign_value(&manifest(&component, &signer), &signer);
    let artifact = verify_artifact(&trust, &signed, &component).unwrap();
    let grant = RawResourceGrant::new("recipient", "customer:debug-primary-secret");
    let grant_debug = format!("{grant:?}");
    assert!(grant_debug.contains("<redacted>"));
    assert!(!grant_debug.contains("recipient"));
    assert!(!grant_debug.contains("customer:debug-primary-secret"));

    let invocation = PreparedInvocation::prepare(
        &artifact,
        &selector(),
        br#"{"recipient":"customer:debug-primary-secret","payload":{"message":"debug-canonical-input-secret","priority":1}}"#,
        vec![grant],
    )
    .unwrap();
    let artifact_debug = format!("{artifact:?}");
    let invocation_debug = format!("{invocation:?}");
    let raw_module_debug = format!("{:?}", artifact.bytes());
    let raw_canonical_input_debug = format!("{:?}", invocation.canonical_input());

    assert!(artifact_debug.contains("<redacted>"));
    assert!(!artifact_debug.contains("phase-b-a"));
    assert!(!artifact_debug.contains(&raw_module_debug));
    assert!(invocation_debug.contains("<redacted>"));
    assert!(!invocation_debug.contains("debug-canonical-input-secret"));
    assert!(!invocation_debug.contains("customer:debug-primary-secret"));
    assert!(!invocation_debug.contains(&raw_canonical_input_debug));
}
