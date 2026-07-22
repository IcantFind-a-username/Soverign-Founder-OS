use super::util::{kernel, now, storage};
use super::*;

use chrono::Duration as ChronoDuration;
use rand::RngCore;
use sovereign_artifact::{
    ArtifactStore, ArtifactVerificationIntent, ArtifactVerifier, Digest, OperationSelector,
    PreparedInvocation, RawResourceGrant, SystemClock as ArtifactClock, MANIFEST_PROTOCOL_VERSION,
};
use sovereign_audit_ledger::hash_bytes;
use sovereign_capability::approval::{approve_invocation, ApprovalClaimsV1, ApprovalGrantRequest};
use sovereign_capability::v2::{
    CapabilityIssuerV2, CapabilityV2IssueOptions, CapabilityV2IssueRequest, CapabilityValidatorV2,
    SystemClock as CapabilityClock,
};
use sovereign_contracts::{AutomationLevel, DataClass};
use sovereign_identity::{
    AdmissionRole, ApprovalRole, AuthorityRole, KeyValidity, PublisherRole, RoleTrustStore,
    TypedSigner,
};
use sovereign_policy::{AuthenticatedPolicyContextV2, PolicyEngine};
use sovereign_sandbox::{VerifiedExecutionRequest, VerifiedSandboxExecutor};
use sovereign_vault::Vault;
use uuid::Uuid;

use crate::demo::compile_wat;

impl Store {
    /// One end-to-end pass of the secure kernel, triggered by the owner's
    /// click: verify the built-in delivery-preparation plugin, admit it into
    /// the local store, prepare the exact invocation for this document, get a
    /// deterministic policy decision (which demands approval), sign RFC 0003
    /// evidence with the owner's approval key, issue a Capability V2 token
    /// from that evidence, and execute the pure-compute step in the verified
    /// sandbox. Every stage fails closed.
    pub(super) fn execute_signed_approval(
        &self,
        document: &Document,
        delivery: &[u8],
    ) -> Result<SignedApprovalRecord, WorkspaceError> {
        let approval_secret = self.owner_secret("owner_approval_key")?;
        let authority_secret = self.owner_secret("runtime_authority_key")?;
        let admission_secret = self.owner_secret("owner_admission_key")?;

        let now_unix = now();
        let validity = KeyValidity::new(now_unix - 60, now_unix + 3_600).map_err(kernel)?;

        // Built-in delivery-preparation tool: publisher-verified, then
        // admitted under the owner's admission key (or reloaded and
        // re-verified from the content-addressed store on later runs).
        let component =
            compile_wat(r#"(module (func (export "sovereign_run") (result i32) i32.const 0))"#);
        let publisher = TypedSigner::<PublisherRole>::from_secret_bytes(
            BUILTIN_PUBLISHER_ISSUER,
            BUILTIN_PUBLISHER_SECRET,
        )
        .map_err(kernel)?;
        let manifest = delivery_manifest_json(&publisher, &component);
        let canonical_manifest = serde_json_canonicalizer::to_vec(&manifest).map_err(kernel)?;
        let signed_manifest = publisher.sign_cose(&canonical_manifest).map_err(kernel)?;
        let mut publishers = RoleTrustStore::<PublisherRole>::new();
        publishers
            .trust_signer(&publisher, validity)
            .map_err(kernel)?;
        let intent = ArtifactVerificationIntent::new(
            BUILTIN_PUBLISHER_ISSUER,
            Digest::of_bytes(&signed_manifest),
            Digest::of_bytes(&component),
        )
        .map_err(kernel)?;
        let artifact = ArtifactVerifier::new(&publishers)
            .verify(&intent, &signed_manifest, &component)
            .map_err(kernel)?;

        let admission_signer = TypedSigner::<AdmissionRole>::from_secret_bytes(
            OWNER_ADMISSION_ISSUER,
            admission_secret,
        )
        .map_err(kernel)?;
        let mut admission_trust = RoleTrustStore::<AdmissionRole>::new();
        admission_trust
            .trust_signer(&admission_signer, validity)
            .map_err(kernel)?;
        let store = ArtifactStore::open(self.root.join("artifacts")).map_err(kernel)?;
        let admitted = match store.admit(&artifact, &admission_signer, &ArtifactClock) {
            Ok(admitted) => admitted,
            Err(sovereign_artifact::ArtifactError::AdmissionRecordExists) => store
                .load(
                    artifact.component_digest(),
                    artifact.manifest_digest(),
                    &admission_trust,
                    OWNER_ADMISSION_ISSUER,
                    &ArtifactClock,
                )
                .map_err(kernel)?,
            Err(error) => return Err(kernel(error)),
        };

        let selector =
            OperationSelector::new("workspace.delivery", "1.0.0", "prepare").map_err(kernel)?;
        let resource = format!("document:{}", document.id);
        let input = serde_json::to_vec(&serde_json::json!({
            "document_id": document.id.to_string(),
            "resource": resource,
        }))
        .map_err(kernel)?;
        let invocation = PreparedInvocation::prepare(
            admitted.artifact(),
            &selector,
            &input,
            vec![RawResourceGrant::new("primary", resource.as_str())],
        )
        .map_err(kernel)?;

        let session_id = Uuid::new_v4();
        let idempotency = Uuid::new_v4();
        let decision = PolicyEngine::new()
            .evaluate_prepared(
                &invocation,
                AuthenticatedPolicyContextV2::new(
                    WORKSPACE_AUDIENCE,
                    "workspace",
                    "founder",
                    session_id,
                    DataClass::Amber,
                    AutomationLevel::L2ApproveExecute,
                    idempotency,
                )
                .map_err(kernel)?,
            )
            .map_err(kernel)?;
        if !decision.allowed() {
            return Err(WorkspaceError::PolicyDenied(
                "delivery preparation denied by policy".into(),
            ));
        }
        if !decision.requires_approval() {
            // Fail closed: this path exists precisely because policy demands
            // a human; if it ever stops demanding one, refuse to proceed.
            return Err(WorkspaceError::PolicyDenied(
                "expected an approval requirement for delivery".into(),
            ));
        }

        let approval_signer =
            TypedSigner::<ApprovalRole>::from_secret_bytes(OWNER_APPROVAL_ISSUER, approval_secret)
                .map_err(kernel)?;
        let signed_approval = approve_invocation(
            &approval_signer,
            &CapabilityClock,
            ApprovalGrantRequest {
                approver_subject_id: "founder-owner",
                audience: WORKSPACE_AUDIENCE,
                venture_id: "workspace",
                subject_id: "founder",
                session_id,
                policy_decision: &decision,
                prepared_invocation: &invocation,
                ttl_seconds: APPROVAL_TTL_SECONDS,
            },
        )
        .map_err(kernel)?;
        let mut approval_trust = RoleTrustStore::<ApprovalRole>::new();
        approval_trust
            .trust_signer(&approval_signer, validity)
            .map_err(kernel)?;
        // Extract the claims for the audit record by verifying our own
        // evidence exactly the way the issuer will.
        let approval_claims: ApprovalClaimsV1 = serde_json::from_slice(
            approval_trust
                .verify(signed_approval.as_bytes(), OWNER_APPROVAL_ISSUER, now())
                .map_err(kernel)?
                .payload(),
        )
        .map_err(kernel)?;

        let authority = TypedSigner::<AuthorityRole>::from_secret_bytes(
            RUNTIME_AUTHORITY_ISSUER,
            authority_secret,
        )
        .map_err(kernel)?;
        let mut authority_trust = RoleTrustStore::<AuthorityRole>::new();
        authority_trust
            .trust_signer(&authority, validity)
            .map_err(kernel)?;
        let mut approval_trust_for_validator = RoleTrustStore::<ApprovalRole>::new();
        approval_trust_for_validator
            .trust_signer(&approval_signer, validity)
            .map_err(kernel)?;

        let issuer = CapabilityIssuerV2::new(authority, WORKSPACE_AUDIENCE, CapabilityClock)
            .map_err(kernel)?
            .with_approval_trust(approval_trust, OWNER_APPROVAL_ISSUER)
            .map_err(kernel)?;
        let token = issuer
            .issue_approved(
                CapabilityV2IssueRequest {
                    venture_id: "workspace",
                    subject_id: "founder",
                    session_id,
                    policy_decision: &decision,
                    prepared_invocation: &invocation,
                    options: CapabilityV2IssueOptions {
                        ttl: ChronoDuration::seconds(60),
                        idempotency_key: idempotency,
                    },
                },
                &signed_approval,
            )
            .map_err(kernel)?;

        let validator = CapabilityValidatorV2::new(
            authority_trust,
            RUNTIME_AUTHORITY_ISSUER,
            WORKSPACE_AUDIENCE,
            CapabilityClock,
        )
        .map_err(kernel)?
        .with_approval_trust(approval_trust_for_validator, OWNER_APPROVAL_ISSUER)
        .map_err(kernel)?
        .with_authority_store(
            sovereign_authority::AuthorityStore::open(self.root.join("authority"))
                .map_err(kernel)?,
        );
        let mut executor = VerifiedSandboxExecutor::new(vec![selector], validator)
            .map_err(kernel)?
            .with_execution_journal(
                sovereign_execution::ExecutionJournal::open(self.root.join("executions"))
                    .map_err(kernel)?,
            );
        let result = executor
            .execute_approved(
                VerifiedExecutionRequest {
                    token: &token,
                    invocation: &invocation,
                    venture_id: "workspace",
                    subject_id: "founder",
                    session_id,
                    policy_decision: &decision,
                },
                Some(&signed_approval),
            )
            .map_err(kernel)?;

        // The first real host effect: with the whole chain verified and the
        // capability durably consumed, write the composed outreach message to
        // the owner's local outbox as an RFC 5322 `.eml`. This is audited and
        // revocable; the message is composed, not transmitted — delivery to the
        // customer remains the founder's own action.
        let outbox =
            sovereign_effects::OutboxBroker::open(self.root.join("outbox")).map_err(kernel)?;
        let receipt = outbox
            .write_message(
                &document.id.simple().to_string(),
                sovereign_effects::EffectDataClass::Amber,
                delivery,
            )
            .map_err(kernel)?;

        Ok(SignedApprovalRecord {
            approval_id: approval_claims.approval_id,
            approver_subject_id: approval_claims.approver_subject_id,
            approver_key_id: approval_claims.approver_key_id.as_hex(),
            evidence_digest: hash_bytes(signed_approval.as_bytes()),
            signed_approval_hex: hex::encode(signed_approval.as_bytes()),
            component_digest: invocation.artifact().component_digest().as_hex(),
            canonical_input_digest: invocation.input_digest().as_hex(),
            capability_idempotency: idempotency,
            guest_exit_code: result.exit_code,
            fuel_consumed: result.fuel_consumed,
            outbox: Some(OutboxWrite {
                relative_path: receipt.relative_path,
                content_sha256: receipt.content_sha256_hex,
                bytes: receipt.bytes,
            }),
        })
    }

    /// Load or create one of the owner's 32-byte signing secrets, stored in
    /// the encrypted vault. Prototype key management: the vault key itself is
    /// a local file in this stage.
    fn owner_secret(&self, name: &str) -> Result<[u8; 32], WorkspaceError> {
        let mut vault = Vault::init(self.root.join("vault")).map_err(storage)?;
        match vault.get(name) {
            Ok(bytes) => bytes
                .try_into()
                .map_err(|_| WorkspaceError::Storage(format!("corrupt key entry `{name}`"))),
            Err(sovereign_vault::VaultError::NotFound(_)) => {
                let mut secret = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut secret);
                vault.put(name, &secret).map_err(storage)?;
                Ok(secret)
            }
            Err(error) => Err(storage(error)),
        }
    }
}

fn delivery_manifest_json(
    publisher: &TypedSigner<PublisherRole>,
    component: &[u8],
) -> serde_json::Value {
    serde_json::json!({
        "protocol_version": MANIFEST_PROTOCOL_VERSION,
        "publisher_issuer": BUILTIN_PUBLISHER_ISSUER,
        "publisher_key_id": Digest::from_bytes(*publisher.key_id()),
        "component_digest": Digest::of_bytes(component),
        "backend": "core_wasm",
        "risk_class": "pure_compute",
        "abi": "sovereign_core_wasm_v1",
        "entrypoint": sovereign_artifact::CORE_WASM_ENTRYPOINT,
        "requested_host_capabilities": [],
        "operations": [{
            "selector": {
                "tool_id": "workspace.delivery",
                "tool_version": "1.0.0",
                "operation_id": "prepare"
            },
            "input_limits": { "max_bytes": 2048, "max_depth": 4 },
            "input_schema": {
                "type": "object",
                "properties": {
                    "document_id": { "type": "string", "max_utf8_bytes": 64 },
                    "resource": { "type": "string", "max_utf8_bytes": 128 }
                },
                "required": ["document_id", "resource"],
                "max_properties": 2
            },
            "resource_bindings": [{
                "binding_id": "primary",
                "json_pointer": "/resource",
                "normalization": "exact_utf8_v1",
                "primary": true
            }]
        }]
    })
}
