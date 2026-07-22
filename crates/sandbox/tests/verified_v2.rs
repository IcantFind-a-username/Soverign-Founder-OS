use chrono::{DateTime, Duration, Utc};
use sovereign_artifact::{
    AdmissionLimits, AdmittedArtifact, ArtifactStore, ArtifactVerificationIntent, ArtifactVerifier,
    Digest, OperationSelector, PreparedInvocation, RawResourceGrant, TrustedClock as ArtifactClock,
    CORE_WASM_ENTRYPOINT, MANIFEST_PROTOCOL_VERSION,
};
use sovereign_capability::v2::{
    CapabilityIssuerV2, CapabilityTokenV2, CapabilityV2Error, CapabilityV2IssueOptions,
    CapabilityV2IssueRequest, CapabilityValidatorV2, TrustedClock as CapabilityClock,
};
use sovereign_capability::{CapabilityIssuer, IssueOptions};
use sovereign_contracts::{
    ActionRequest, AutomationLevel, CapabilityToken, DataClass, PolicyDecision,
};
use sovereign_identity::{
    AdmissionRole, AuthorityRole, KeyValidity, PublisherRole, RoleTrustStore, TypedSigner,
};
use sovereign_policy::{AuthenticatedPolicyContextV2, PolicyAuthorizationV2, PolicyEngine};
use sovereign_sandbox::{
    ExecutionRuntime, SandboxError, SandboxExecutor, VerifiedExecutionRequest,
    VerifiedSandboxExecutor, WasmExecutionRequest,
};
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;
const PUBLISHER_ISSUER: &str = "publisher.local";
const AUTHORITY_ISSUER: &str = "authority.local";
const AUDIENCE: &str = "sovereign-runtime";
const VENTURE: &str = "venture-alpha";
const SUBJECT: &str = "founder-session-subject";
const RESOURCE: &str = "draft:alpha";
const PUBLISHER_SECRET: [u8; 32] = [0x50; 32];
const AUTHORITY_SECRET: [u8; 32] = [0x41; 32];
const ADMISSION_ISSUER: &str = "device.local";
const ADMISSION_SECRET: [u8; 32] = [0x44; 32];

#[derive(Debug, Clone, Copy)]
struct FixedClock(i64);

impl ArtifactClock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.0
    }
}

impl CapabilityClock for FixedClock {
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

fn wasm_returning(exit_code: i32) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module (func (export "sovereign_run") (result i32) i32.const {exit_code}))"#
    ))
    .unwrap()
}

fn wasm_trapping() -> Vec<u8> {
    wat::parse_str(r#"(module (func (export "sovereign_run") (result i32) unreachable))"#).unwrap()
}

fn admit_and_prepare(component: &[u8], content: &str) -> (PreparedInvocation, AdmittedArtifact) {
    let publisher =
        TypedSigner::<PublisherRole>::from_secret_bytes(PUBLISHER_ISSUER, PUBLISHER_SECRET)
            .unwrap();
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
        PUBLISHER_ISSUER,
        Digest::of_bytes(&signed_manifest),
        Digest::of_bytes(component),
    )
    .unwrap();
    let artifact =
        ArtifactVerifier::with_clock(&publishers, AdmissionLimits::default(), FixedClock(NOW))
            .verify(&intent, &signed_manifest, component)
            .unwrap();
    let input = serde_json::to_vec(&serde_json::json!({
        "content": content,
        "resource": RESOURCE
    }))
    .unwrap();
    // The executor requires the owner-admitted handle (RFC 0002 step 8):
    // admit through a throwaway content-addressed store.
    let dir = tempfile::tempdir().unwrap();
    let admission_signer =
        TypedSigner::<AdmissionRole>::from_secret_bytes(ADMISSION_ISSUER, ADMISSION_SECRET)
            .unwrap();
    let store = ArtifactStore::open(dir.path()).unwrap();
    let admitted = store
        .admit(&artifact, &admission_signer, &FixedClock(NOW))
        .unwrap();
    let invocation = PreparedInvocation::prepare(
        &artifact,
        &selector(),
        &input,
        vec![RawResourceGrant::new("primary", RESOURCE)],
    )
    .unwrap();
    (invocation, admitted)
}

fn decision(invocation: &PreparedInvocation) -> PolicyAuthorizationV2 {
    PolicyEngine::with_clock(FixedClock(NOW))
        .evaluate_prepared(
            invocation,
            AuthenticatedPolicyContextV2::new(
                AUDIENCE,
                VENTURE,
                SUBJECT,
                Uuid::from_u128(1),
                DataClass::Green,
                AutomationLevel::L1Draft,
                Uuid::from_u128(2),
            )
            .unwrap(),
        )
        .unwrap()
}

fn authority() -> (
    CapabilityIssuerV2<FixedClock>,
    CapabilityValidatorV2<FixedClock>,
) {
    let trusted =
        TypedSigner::<AuthorityRole>::from_secret_bytes(AUTHORITY_ISSUER, AUTHORITY_SECRET)
            .unwrap();
    let mut trust_store = RoleTrustStore::<AuthorityRole>::new();
    trust_store
        .trust_signer(&trusted, KeyValidity::new(NOW - 60, NOW + 3_600).unwrap())
        .unwrap();
    let issuer = CapabilityIssuerV2::new(
        TypedSigner::<AuthorityRole>::from_secret_bytes(AUTHORITY_ISSUER, AUTHORITY_SECRET)
            .unwrap(),
        AUDIENCE,
        FixedClock(NOW),
    )
    .unwrap();
    let validator =
        CapabilityValidatorV2::new(trust_store, AUTHORITY_ISSUER, AUDIENCE, FixedClock(NOW))
            .unwrap();
    (issuer, validator)
}

fn issue(
    issuer: &CapabilityIssuerV2<FixedClock>,
    invocation: &PreparedInvocation,
    policy_decision: &PolicyAuthorizationV2,
    _session_id: Uuid,
) -> CapabilityTokenV2 {
    issuer
        .issue(CapabilityV2IssueRequest {
            venture_id: VENTURE,
            subject_id: SUBJECT,
            session_id: policy_decision.session_id(),
            policy_decision,
            prepared_invocation: invocation,
            options: CapabilityV2IssueOptions {
                ttl: Duration::seconds(60),
                idempotency_key: policy_decision.idempotency_key(),
            },
        })
        .unwrap()
}

fn request<'a>(
    token: &'a CapabilityTokenV2,
    invocation: &'a PreparedInvocation,
    admitted: &'a AdmittedArtifact,
    policy_decision: &'a PolicyAuthorizationV2,
    _session_id: Uuid,
) -> VerifiedExecutionRequest<'a> {
    VerifiedExecutionRequest {
        token,
        invocation,
        admitted,
        venture_id: VENTURE,
        subject_id: SUBJECT,
        session_id: policy_decision.session_id(),
        policy_decision,
    }
}

#[test]
fn executor_refuses_a_mismatched_admitted_handle_without_consuming_the_token() {
    let (invocation, admitted) = admit_and_prepare(&wasm_returning(17), "first input");
    let (_other_invocation, other_admitted) = admit_and_prepare(&wasm_returning(3), "other input");
    let policy_decision = decision(&invocation);
    let session_id = Uuid::new_v4();
    let (issuer, validator) = authority();
    let token = issue(&issuer, &invocation, &policy_decision, session_id);
    let mut executor = VerifiedSandboxExecutor::new(vec![selector()], validator).unwrap();

    // An admitted handle for a *different* artifact is refused before the
    // journal opens or the one-use capability is consumed.
    assert!(matches!(
        executor.execute(request(
            &token,
            &invocation,
            &other_admitted,
            &policy_decision,
            session_id,
        )),
        Err(SandboxError::ArtifactNotAdmitted)
    ));

    // Nothing was burned: the same token still runs with the right handle.
    let result = executor
        .execute(request(
            &token,
            &invocation,
            &admitted,
            &policy_decision,
            session_id,
        ))
        .unwrap();
    assert_eq!(result.exit_code, 17);
}

#[test]
fn signed_verified_prepared_capability_executes_exact_artifact() {
    let (invocation, admitted) = admit_and_prepare(&wasm_returning(17), "first input");
    let policy_decision = decision(&invocation);
    let session_id = Uuid::new_v4();
    let (issuer, validator) = authority();
    let token = issue(&issuer, &invocation, &policy_decision, session_id);
    let mut executor = VerifiedSandboxExecutor::new(vec![selector()], validator).unwrap();

    let result = executor
        .execute(request(
            &token,
            &invocation,
            &admitted,
            &policy_decision,
            session_id,
        ))
        .unwrap();
    assert_eq!(result.exit_code, 17);
    assert_eq!(
        result.runtime,
        ExecutionRuntime::WasmtimeVerifiedPureComputeV2
    );
    assert!(result.runtime.is_isolated());
    assert!(!result.runtime.is_production_ready());
}

#[test]
fn artifact_and_input_substitution_are_denied_before_guest_startup() {
    let original_module = wasm_returning(0);
    let (original, original_admitted) = admit_and_prepare(&original_module, "authorized input");
    let (substituted_artifact, substituted_admitted) =
        admit_and_prepare(&wasm_trapping(), "authorized input");
    let (substituted_input, substituted_input_admitted) =
        admit_and_prepare(&original_module, "substituted input");
    let policy_decision = decision(&original);
    let session_id = Uuid::new_v4();
    let (issuer, validator) = authority();
    let token = issue(&issuer, &original, &policy_decision, session_id);
    let mut executor = VerifiedSandboxExecutor::new(vec![selector()], validator).unwrap();

    assert!(matches!(
        executor.execute(request(
            &token,
            &substituted_artifact,
            &substituted_admitted,
            &policy_decision,
            session_id,
        )),
        Err(SandboxError::CapabilityV2(
            CapabilityV2Error::InvocationMismatch("component_digest")
        ))
    ));
    assert!(matches!(
        executor.execute(request(
            &token,
            &substituted_input,
            &substituted_input_admitted,
            &policy_decision,
            session_id,
        )),
        Err(SandboxError::CapabilityV2(
            CapabilityV2Error::InvocationMismatch("canonical_input_digest")
        ))
    ));

    let valid = executor
        .execute(request(
            &token,
            &original,
            &original_admitted,
            &policy_decision,
            session_id,
        ))
        .unwrap();
    assert_eq!(valid.exit_code, 0);
}

#[test]
fn structured_allowlist_does_not_accept_dotted_string_collision() {
    let (invocation, admitted) = admit_and_prepare(&wasm_returning(0), "first input");
    let policy_decision = decision(&invocation);
    let session_id = Uuid::new_v4();
    let (issuer, validator) = authority();
    let token = issue(&issuer, &invocation, &policy_decision, session_id);
    let ambiguous_if_flattened =
        OperationSelector::new("document", "1.0.0", "transform.render").unwrap();
    let mut executor =
        VerifiedSandboxExecutor::new(vec![ambiguous_if_flattened], validator).unwrap();

    let error = executor
        .execute(request(
            &token,
            &invocation,
            &admitted,
            &policy_decision,
            session_id,
        ))
        .unwrap_err();
    assert!(matches!(
        error,
        SandboxError::VerifiedOperationNotAllowed { selector: denied }
            if denied == selector()
    ));
}

#[test]
fn guest_failure_still_consumes_v2_capability() {
    let (invocation, admitted) = admit_and_prepare(&wasm_trapping(), "first input");
    let policy_decision = decision(&invocation);
    let session_id = Uuid::new_v4();
    let (issuer, validator) = authority();
    let token = issue(&issuer, &invocation, &policy_decision, session_id);
    let mut executor = VerifiedSandboxExecutor::new(vec![selector()], validator).unwrap();

    assert!(matches!(
        executor.execute(request(
            &token,
            &invocation,
            &admitted,
            &policy_decision,
            session_id
        )),
        Err(SandboxError::GuestTrap(_))
    ));
    assert!(matches!(
        executor.execute(request(
            &token,
            &invocation,
            &admitted,
            &policy_decision,
            session_id
        )),
        Err(SandboxError::CapabilityV2(CapabilityV2Error::Replay))
    ));
}

fn legacy_token() -> (CapabilityIssuer, CapabilityToken, PolicyDecision) {
    let policy_decision = PolicyEngine::new().evaluate(ActionRequest {
        actor_id: SUBJECT.into(),
        venture_id: VENTURE.into(),
        tool: "document".into(),
        operation: "transform".into(),
        resource: RESOURCE.into(),
        data_class: DataClass::Green,
        automation_level: AutomationLevel::L1Draft,
    });
    let issuer = CapabilityIssuer::new();
    let token = issuer
        .issue(&policy_decision, IssueOptions::default(), false)
        .unwrap();
    (issuer, token, policy_decision)
}

#[test]
fn v1_token_remains_on_legacy_executor_and_runtime_only() {
    let (issuer, token, _decision) = legacy_token();
    let module = wasm_returning(3);
    let mut executor =
        SandboxExecutor::new(vec!["document.transform".into()], issuer.public_key_b64()).unwrap();
    let result = executor
        .execute_wasm(WasmExecutionRequest {
            token: &token,
            venture_id: VENTURE,
            actor_id: SUBJECT,
            tool: "document",
            operation: "transform",
            resource: RESOURCE,
            module: &module,
        })
        .unwrap();
    assert_eq!(result.runtime, ExecutionRuntime::WasmtimeCorePhaseA);
    assert_ne!(
        result.runtime,
        ExecutionRuntime::WasmtimeVerifiedPureComputeV2
    );
}

#[test]
fn execution_journal_records_completed_run() {
    let dir = tempfile::tempdir().unwrap();
    let (invocation, admitted) = admit_and_prepare(&wasm_returning(9), "journal input");
    let policy_decision = decision(&invocation);
    let session_id = Uuid::new_v4();
    let (issuer, validator) = authority();
    let token = issue(&issuer, &invocation, &policy_decision, session_id);
    let mut executor = VerifiedSandboxExecutor::new(vec![selector()], validator)
        .unwrap()
        .with_execution_journal(sovereign_execution::ExecutionJournal::open(dir.path()).unwrap());

    let result = executor
        .execute(request(
            &token,
            &invocation,
            &admitted,
            &policy_decision,
            session_id,
        ))
        .unwrap();
    assert_eq!(result.exit_code, 9);

    let recovered = sovereign_execution::ExecutionJournal::open(dir.path())
        .unwrap()
        .recover()
        .unwrap();
    assert_eq!(recovered.len(), 1);
    assert!(matches!(
        recovered[0].state,
        sovereign_execution::ExecutionState::Completed { .. }
    ));
    assert_eq!(
        recovered[0].intent.component_digest_hex,
        invocation.artifact().component_digest().as_hex()
    );
}

#[test]
fn execution_journal_records_guest_trap_as_failed_not_indeterminate() {
    let dir = tempfile::tempdir().unwrap();
    let (invocation, admitted) = admit_and_prepare(&wasm_trapping(), "journal input");
    let policy_decision = decision(&invocation);
    let session_id = Uuid::new_v4();
    let (issuer, validator) = authority();
    let token = issue(&issuer, &invocation, &policy_decision, session_id);
    let mut executor = VerifiedSandboxExecutor::new(vec![selector()], validator)
        .unwrap()
        .with_execution_journal(sovereign_execution::ExecutionJournal::open(dir.path()).unwrap());

    assert!(matches!(
        executor.execute(request(
            &token,
            &invocation,
            &admitted,
            &policy_decision,
            session_id
        )),
        Err(SandboxError::GuestTrap(_))
    ));

    let recovered = sovereign_execution::ExecutionJournal::open(dir.path())
        .unwrap()
        .recover()
        .unwrap();
    assert_eq!(recovered.len(), 1);
    // A trapped guest is a definite failure, never indeterminate: the
    // terminal record was flushed.
    assert_eq!(
        recovered[0].state,
        sovereign_execution::ExecutionState::Failed {
            code: "guest_trap".into()
        }
    );
}
