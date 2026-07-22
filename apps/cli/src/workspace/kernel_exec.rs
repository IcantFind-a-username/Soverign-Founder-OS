use super::util::{kernel, now, storage};
use super::*;

use chrono::Duration as ChronoDuration;
use rand::RngCore;
use sovereign_artifact::{
    AdmittedArtifact, ArtifactStore, ArtifactVerificationIntent, ArtifactVerifier, Digest,
    OperationSelector, PreparedInvocation, RawResourceGrant, SystemClock as ArtifactClock,
    MANIFEST_PROTOCOL_VERSION,
};
use sovereign_audit_ledger::hash_bytes;
use sovereign_capability::approval::{
    approve_invocation, ApprovalClaimsV1, ApprovalGrantRequest, SignedApprovalV1,
};
use sovereign_capability::v2::{
    CapabilityIssuerV2, CapabilityTokenV2, CapabilityV2IssueOptions, CapabilityV2IssueRequest,
    CapabilityValidatorV2, SystemClock as CapabilityClock,
};
use sovereign_contracts::{AutomationLevel, DataClass};
use sovereign_effects::OutboxReceipt;
use sovereign_identity::{
    AdmissionRole, ApprovalRole, AuthorityRole, KeyValidity, PublisherRole, RoleTrustStore,
    TypedSigner,
};
use sovereign_policy::{AuthenticatedPolicyContextV2, PolicyAuthorizationV2, PolicyEngine};
use sovereign_sandbox::{VerifiedExecutionRequest, VerifiedSandboxExecutor, WasmExecutionResult};
use sovereign_vault::Vault;
use uuid::Uuid;

use crate::demo::compile_wat;

/// The owner's freshly signed approval: the evidence bytes, the claims
/// re-verified out of them, and the signer so downstream trust stores can
/// anchor to the same key.
struct OwnerApproval {
    signer: TypedSigner<ApprovalRole>,
    evidence: SignedApprovalV1,
    claims: ApprovalClaimsV1,
}

impl Store {
    /// One end-to-end pass of the secure kernel, triggered by the owner's
    /// click: verify the built-in delivery-preparation plugin, admit it into
    /// the local store, prepare the exact invocation for this document, get a
    /// deterministic policy decision (which demands approval), sign RFC 0003
    /// evidence with the owner's approval key, issue a Capability V2 token
    /// from that evidence, and execute the pure-compute step in the verified
    /// sandbox. Every stage fails closed; each stage below is its own
    /// function so the chain reads — and reviews — as the RFC describes it.
    pub(super) fn execute_signed_approval(
        &self,
        document: &Document,
        delivery: &[u8],
    ) -> Result<SignedApprovalRecord, WorkspaceError> {
        let now_unix = now();
        let validity = KeyValidity::new(now_unix - 60, now_unix + 3_600).map_err(kernel)?;
        let session_id = Uuid::new_v4();
        let idempotency = Uuid::new_v4();

        let admitted = self.admit_delivery_tool(validity)?;
        let (selector, invocation) = prepare_delivery_invocation(&admitted, document)?;
        let decision = evaluate_delivery_policy(&invocation, session_id, idempotency)?;
        let approval = self.sign_owner_approval(&invocation, &decision, session_id)?;
        let token = self.issue_delivery_capability(
            &approval,
            &invocation,
            &decision,
            session_id,
            idempotency,
            validity,
        )?;
        let result = self.execute_in_sandbox(
            selector,
            &admitted,
            &approval,
            &token,
            &invocation,
            &decision,
            session_id,
            validity,
        )?;
        let receipt = self.write_outbox_effect(document, delivery)?;

        Ok(assemble_record(
            approval,
            &invocation,
            idempotency,
            &result,
            receipt,
        ))
    }

    /// Stage 1 — supply chain: publisher-verify the built-in
    /// delivery-preparation tool, then admit it under the owner's admission
    /// key (or reload and re-verify it from the content-addressed store on
    /// later runs).
    fn admit_delivery_tool(
        &self,
        validity: KeyValidity,
    ) -> Result<AdmittedArtifact, WorkspaceError> {
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

        let admission_secret = self.owner_secret("owner_admission_key")?;
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
        match store.admit(&artifact, &admission_signer, &ArtifactClock) {
            Ok(admitted) => Ok(admitted),
            Err(sovereign_artifact::ArtifactError::AdmissionRecordExists) => store
                .load(
                    artifact.component_digest(),
                    artifact.manifest_digest(),
                    &admission_trust,
                    OWNER_ADMISSION_ISSUER,
                    &ArtifactClock,
                )
                .map_err(kernel),
            Err(error) => Err(kernel(error)),
        }
    }

    /// Stage 4 — the human decision made durable: sign RFC 0003 approval
    /// evidence with the owner's key, then re-verify our own evidence exactly
    /// the way the issuer will and extract its claims for the audit record.
    fn sign_owner_approval(
        &self,
        invocation: &PreparedInvocation,
        decision: &PolicyAuthorizationV2,
        session_id: Uuid,
    ) -> Result<OwnerApproval, WorkspaceError> {
        let approval_secret = self.owner_secret("owner_approval_key")?;
        let signer =
            TypedSigner::<ApprovalRole>::from_secret_bytes(OWNER_APPROVAL_ISSUER, approval_secret)
                .map_err(kernel)?;
        let evidence = approve_invocation(
            &signer,
            &CapabilityClock,
            ApprovalGrantRequest {
                approver_subject_id: "founder-owner",
                audience: WORKSPACE_AUDIENCE,
                venture_id: "workspace",
                subject_id: "founder",
                session_id,
                policy_decision: decision,
                prepared_invocation: invocation,
                ttl_seconds: APPROVAL_TTL_SECONDS,
            },
        )
        .map_err(kernel)?;
        let mut approval_trust = RoleTrustStore::<ApprovalRole>::new();
        approval_trust
            .trust_signer(
                &signer,
                KeyValidity::new(now() - 60, now() + 3_600).map_err(kernel)?,
            )
            .map_err(kernel)?;
        let claims: ApprovalClaimsV1 = serde_json::from_slice(
            approval_trust
                .verify(evidence.as_bytes(), OWNER_APPROVAL_ISSUER, now())
                .map_err(kernel)?
                .payload(),
        )
        .map_err(kernel)?;
        Ok(OwnerApproval {
            signer,
            evidence,
            claims,
        })
    }

    /// Stage 5 — authorization: issue an exact, one-use Capability V2 token
    /// from the signed approval evidence.
    fn issue_delivery_capability(
        &self,
        approval: &OwnerApproval,
        invocation: &PreparedInvocation,
        decision: &PolicyAuthorizationV2,
        session_id: Uuid,
        idempotency: Uuid,
        validity: KeyValidity,
    ) -> Result<CapabilityTokenV2, WorkspaceError> {
        let authority_secret = self.owner_secret("runtime_authority_key")?;
        let authority = TypedSigner::<AuthorityRole>::from_secret_bytes(
            RUNTIME_AUTHORITY_ISSUER,
            authority_secret,
        )
        .map_err(kernel)?;
        let mut approval_trust = RoleTrustStore::<ApprovalRole>::new();
        approval_trust
            .trust_signer(&approval.signer, validity)
            .map_err(kernel)?;
        let issuer = CapabilityIssuerV2::new(authority, WORKSPACE_AUDIENCE, CapabilityClock)
            .map_err(kernel)?
            .with_approval_trust(approval_trust, OWNER_APPROVAL_ISSUER)
            .map_err(kernel)?;
        issuer
            .issue_approved(
                CapabilityV2IssueRequest {
                    venture_id: "workspace",
                    subject_id: "founder",
                    session_id,
                    policy_decision: decision,
                    prepared_invocation: invocation,
                    options: CapabilityV2IssueOptions {
                        ttl: ChronoDuration::seconds(60),
                        idempotency_key: idempotency,
                    },
                },
                &approval.evidence,
            )
            .map_err(kernel)
    }

    /// Stage 6 — execution: validate the token against the durable Authority
    /// Store (one use, ever) and run the pure-compute step in the verified
    /// Wasmtime sandbox with a crash-safe execution journal.
    #[allow(clippy::too_many_arguments)]
    fn execute_in_sandbox(
        &self,
        selector: OperationSelector,
        admitted: &AdmittedArtifact,
        approval: &OwnerApproval,
        token: &CapabilityTokenV2,
        invocation: &PreparedInvocation,
        decision: &PolicyAuthorizationV2,
        session_id: Uuid,
        validity: KeyValidity,
    ) -> Result<WasmExecutionResult, WorkspaceError> {
        let authority_secret = self.owner_secret("runtime_authority_key")?;
        let authority = TypedSigner::<AuthorityRole>::from_secret_bytes(
            RUNTIME_AUTHORITY_ISSUER,
            authority_secret,
        )
        .map_err(kernel)?;
        let mut authority_trust = RoleTrustStore::<AuthorityRole>::new();
        authority_trust
            .trust_signer(&authority, validity)
            .map_err(kernel)?;
        let mut approval_trust = RoleTrustStore::<ApprovalRole>::new();
        approval_trust
            .trust_signer(&approval.signer, validity)
            .map_err(kernel)?;
        let validator = CapabilityValidatorV2::new(
            authority_trust,
            RUNTIME_AUTHORITY_ISSUER,
            WORKSPACE_AUDIENCE,
            CapabilityClock,
        )
        .map_err(kernel)?
        .with_approval_trust(approval_trust, OWNER_APPROVAL_ISSUER)
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
        executor
            .execute_approved(
                VerifiedExecutionRequest {
                    token,
                    invocation,
                    admitted,
                    venture_id: "workspace",
                    subject_id: "founder",
                    session_id,
                    policy_decision: decision,
                },
                Some(&approval.evidence),
            )
            .map_err(kernel)
    }

    /// Stage 7 — the first real host effect: with the whole chain verified
    /// and the capability durably consumed, write the composed message to the
    /// owner's local outbox as an RFC 5322 `.eml`. Audited and revocable; the
    /// message is composed, not transmitted — delivery to the customer
    /// remains the founder's own action.
    fn write_outbox_effect(
        &self,
        document: &Document,
        delivery: &[u8],
    ) -> Result<OutboxReceipt, WorkspaceError> {
        let outbox =
            sovereign_effects::OutboxBroker::open(self.root.join("outbox")).map_err(kernel)?;
        outbox
            .write_message(
                &document.id.simple().to_string(),
                sovereign_effects::EffectDataClass::Amber,
                delivery,
            )
            .map_err(kernel)
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

/// Stage 2 — exactness: bind this document's canonical input and resource
/// grant into a prepared invocation of the admitted tool.
fn prepare_delivery_invocation(
    admitted: &AdmittedArtifact,
    document: &Document,
) -> Result<(OperationSelector, PreparedInvocation), WorkspaceError> {
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
    Ok((selector, invocation))
}

/// Stage 3 — deterministic policy: evaluate the prepared invocation and fail
/// closed unless it is allowed *and* demands a human approval. This path
/// exists precisely because policy demands a human; if it ever stops
/// demanding one, refuse to proceed.
fn evaluate_delivery_policy(
    invocation: &PreparedInvocation,
    session_id: Uuid,
    idempotency: Uuid,
) -> Result<PolicyAuthorizationV2, WorkspaceError> {
    let decision = PolicyEngine::new()
        .evaluate_prepared(
            invocation,
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
        return Err(WorkspaceError::PolicyDenied(
            "expected an approval requirement for delivery".into(),
        ));
    }
    Ok(decision)
}

/// Assemble the evidence record persisted onto the approval: everything the
/// owner (or an auditor) needs to re-verify what ran and what it produced.
fn assemble_record(
    approval: OwnerApproval,
    invocation: &PreparedInvocation,
    idempotency: Uuid,
    result: &WasmExecutionResult,
    receipt: OutboxReceipt,
) -> SignedApprovalRecord {
    SignedApprovalRecord {
        approval_id: approval.claims.approval_id,
        approver_subject_id: approval.claims.approver_subject_id,
        approver_key_id: approval.claims.approver_key_id.as_hex(),
        evidence_digest: hash_bytes(approval.evidence.as_bytes()),
        signed_approval_hex: hex::encode(approval.evidence.as_bytes()),
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
