//! Story-driven Stage 1 secure-kernel demo.
//!
//! Everything printed as ✓ or ✗ is a real code path: real Ed25519/COSE
//! signatures, real strict-schema validation, real Capability V2 issuance and
//! consumption, real Wasmtime execution with fuel metering, and a real signed
//! audit chain. Nothing in this demo simulates an enforcement decision.
//!
//! Honest boundaries, printed to the user as well: the demo uses hard-coded
//! demo keys (not production trust anchors), replay defense is process-local,
//! the guest does not yet receive the authorized input bytes, and no external
//! effect is ever performed — effectful requests fail closed.

use std::io::Write as _;
use std::path::PathBuf;

use chrono::Duration;
use sovereign_artifact::{
    AdmittedArtifact, ArtifactError, ArtifactStore, ArtifactVerificationIntent, ArtifactVerifier,
    Digest, OperationSelector, PreparedInvocation, RawResourceGrant, SystemClock as ArtifactClock,
    VerifiedArtifact, CORE_WASM_ENTRYPOINT, MANIFEST_PROTOCOL_VERSION,
};
use sovereign_audit_ledger::{hash_bytes, AppendInput, AuditLedger};
use sovereign_capability::v2::{
    CapabilityIssuerV2, CapabilityTokenV2, CapabilityV2Error, CapabilityV2IssueOptions,
    CapabilityV2IssueRequest, CapabilityValidatorV2, SystemClock as CapabilityClock,
};
use sovereign_contracts::{ActionRequest, AutomationLevel, DataClass};
use sovereign_identity::{
    AdmissionRole, AuthorityRole, DeviceIdentity, KeyValidity, PublisherRole, RoleTrustStore,
    TypedSigner,
};
use sovereign_policy::{AuthenticatedPolicyContextV2, PolicyAuthorizationV2, PolicyEngine};
use sovereign_sandbox::{SandboxError, VerifiedExecutionRequest, VerifiedSandboxExecutor};
use uuid::Uuid;

// Hard-coded demo signing keys. These are deliberately public and constant so
// the demo is deterministic and re-runnable; they are NOT production trust
// anchors and grant nothing outside this demo's ephemeral trust stores.
pub(crate) const DEMO_PUBLISHER_SECRET: [u8; 32] = *b"sovereign-demo-publisher-key-01!";
pub(crate) const DEMO_AUTHORITY_SECRET: [u8; 32] = *b"sovereign-demo-authority-key-01!";
pub(crate) const DEMO_ADMISSION_SECRET: [u8; 32] = *b"sovereign-demo-admission-key-01!";
pub(crate) const DEMO_CACHE_SECRET: [u8; 32] = *b"sovereign-demo-cache-signkey-01!";

pub(crate) const PUBLISHER_ISSUER: &str = "plugin-studio.example";
pub(crate) const AUTHORITY_ISSUER: &str = "sovereign-runtime.local";
pub(crate) const ADMISSION_ISSUER: &str = "founder-device.local";
pub(crate) const CACHE_ISSUER: &str = "founder-device.cache";
pub(crate) const AUDIENCE: &str = "sovereign-runtime";
pub(crate) const VENTURE: &str = "ven_acme_consulting";
pub(crate) const SUBJECT: &str = "founder";

pub(crate) const INVOICE_RESOURCE: &str = "invoice:acme-2026-001";

struct Demo {
    fast: bool,
    root: PathBuf,
    session_id: Uuid,
    publisher: TypedSigner<PublisherRole>,
    publishers: RoleTrustStore<PublisherRole>,
    admission_signer: TypedSigner<AdmissionRole>,
    admission_trust: RoleTrustStore<AdmissionRole>,
    issuer: CapabilityIssuerV2<CapabilityClock>,
    policy: PolicyEngine,
}

pub fn run(fast: bool, root: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let now_unix = chrono::Utc::now().timestamp();
    let validity = KeyValidity::new(now_unix - 60, now_unix + 3_600)?;

    let publisher =
        TypedSigner::<PublisherRole>::from_secret_bytes(PUBLISHER_ISSUER, DEMO_PUBLISHER_SECRET)?;
    let mut publishers = RoleTrustStore::<PublisherRole>::new();
    publishers.trust_signer(&publisher, validity)?;

    let admission_signer =
        TypedSigner::<AdmissionRole>::from_secret_bytes(ADMISSION_ISSUER, DEMO_ADMISSION_SECRET)?;
    let mut admission_trust = RoleTrustStore::<AdmissionRole>::new();
    admission_trust.trust_signer(&admission_signer, validity)?;

    let authority =
        TypedSigner::<AuthorityRole>::from_secret_bytes(AUTHORITY_ISSUER, DEMO_AUTHORITY_SECRET)?;
    let mut authority_trust = RoleTrustStore::<AuthorityRole>::new();
    authority_trust.trust_signer(&authority, validity)?;
    let issuer = CapabilityIssuerV2::new(authority, AUDIENCE, CapabilityClock)?;
    let validator =
        CapabilityValidatorV2::new(authority_trust, AUTHORITY_ISSUER, AUDIENCE, CapabilityClock)?;

    let demo = Demo {
        fast,
        root,
        session_id: Uuid::new_v4(),
        publisher,
        publishers,
        admission_signer,
        admission_trust,
        issuer,
        policy: PolicyEngine::new(),
    };
    demo.run(validator)
}

impl Demo {
    fn run(
        &self,
        validator: CapabilityValidatorV2<CapabilityClock>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        banner();
        self.pause();

        let (device, mut ledger) = self.act_1_trust_root()?;
        self.pause();

        let invoice_plugin = self.act_2_install_plugin()?;
        self.pause();

        let stress_plugin = self.admit_stress_plugin()?;
        let invoice_selector = OperationSelector::new("invoice.tools", "1.0.0", "validate")?;
        let stress_selector = OperationSelector::new("demo.stress", "1.0.0", "spin")?;
        let mut executor = VerifiedSandboxExecutor::new(
            vec![invoice_selector.clone(), stress_selector.clone()],
            validator,
        )?;

        let (invocation, decision, used_token) = self.act_3_real_work(
            &invoice_plugin,
            &invoice_selector,
            &mut executor,
            &device,
            &mut ledger,
        )?;
        self.pause();

        self.act_4_attack_gauntlet(
            &invoice_plugin,
            &stress_plugin,
            &invoice_selector,
            &stress_selector,
            &invocation,
            &decision,
            &used_token,
            &mut executor,
            &ledger,
            &device,
        )?;
        self.pause();

        act_5_takeaway();
        Ok(())
    }

    fn act_1_trust_root(
        &self,
    ) -> Result<(DeviceIdentity, AuditLedger), Box<dyn std::error::Error>> {
        act(1, "Your company gets a local trust root");
        std::fs::create_dir_all(&self.root)?;

        let device_path = self.root.join("device.json");
        let device = if device_path.exists() {
            DeviceIdentity::load(&device_path)?
        } else {
            let device = DeviceIdentity::generate();
            device.save(&device_path)?;
            device
        };
        ok(&format!(
            "device identity {} (Ed25519, stored only on this machine)",
            device.device_id()
        ));

        let mut vault = sovereign_vault::Vault::init(self.root.join("vault"))?;
        vault.put(
            "venture_profile",
            br#"{"name":"Acme Consulting","stage":"customer_validation"}"#,
        )?;
        ok("encrypted vault (AES-256-GCM): venture profile stored locally");

        let ledger_path = self.root.join("ledger.json");
        let ledger = if ledger_path.exists() {
            AuditLedger::load(&ledger_path, device.public_key_b64())?
        } else {
            AuditLedger::new()
        };
        ok(&format!(
            "append-only signed audit ledger ({} prior events, chain verified on load)",
            ledger.events().len()
        ));
        note("No cloud account was created. Nothing left this machine.");
        Ok((device, ledger))
    }

    fn act_2_install_plugin(&self) -> Result<AdmittedArtifact, Box<dyn std::error::Error>> {
        act(2, "Install a plugin — provenance, then permission");
        say("A plugin studio publishes `invoice.tools v1.0.0`. Installing it is");
        say("two separate trust decisions, and both leave cryptographic proof:");

        let component = compile_wat(
            r#"(module
                (func (export "sovereign_run") (result i32)
                    i32.const 0))"#,
        );
        let manifest_json = invoice_manifest_json(&self.publisher, &component);
        let (artifact, signed_manifest) = self.verify_plugin(&manifest_json, &component)?;
        ok("publisher signature verified (COSE_Sign1 / Ed25519, strict RFC 8785 manifest)");
        ok(&format!(
            "component digest pinned: {}",
            short(artifact.component_digest())
        ));

        let admitted = self.admit(&artifact)?;
        ok(&format!(
            "locally admitted: owner key signed admission record {} in the content-addressed store",
            admitted.admission_id()
        ));
        note("The publisher proved WHO built it. Only YOUR key installed it.");

        step("Attack — supply chain: one byte of the plugin is flipped after signing:");
        let mut tampered = component.clone();
        *tampered.last_mut().expect("demo module is non-empty") ^= 0x01;
        let intent = ArtifactVerificationIntent::new(
            PUBLISHER_ISSUER,
            Digest::of_bytes(&signed_manifest),
            Digest::of_bytes(&component),
        )?;
        match ArtifactVerifier::new(&self.publishers).verify(&intent, &signed_manifest, &tampered) {
            Err(ArtifactError::ComponentDigestMismatch { .. }) => {
                deny("rejected: component digest mismatch — modified bytes never execute")
            }
            other => return Err(violation("tampered plugin", &format!("{other:?}"))),
        }
        Ok(admitted)
    }

    fn admit_stress_plugin(&self) -> Result<AdmittedArtifact, Box<dyn std::error::Error>> {
        // A second, hostile plugin used later in the gauntlet. Its manifest is
        // honest (pure compute, no capabilities) but its code spins forever.
        let component = compile_wat(
            r#"(module
                (func (export "sovereign_run") (result i32)
                    (loop $forever
                        i32.const 1
                        drop
                        br $forever)
                    unreachable))"#,
        );
        let manifest_json = stress_manifest_json(&self.publisher, &component);
        let (artifact, _) = self.verify_plugin(&manifest_json, &component)?;
        self.admit(&artifact)
    }

    #[allow(clippy::too_many_arguments)]
    fn act_3_real_work(
        &self,
        plugin: &AdmittedArtifact,
        selector: &OperationSelector,
        executor: &mut VerifiedSandboxExecutor<CapabilityClock>,
        device: &DeviceIdentity,
        ledger: &mut AuditLedger,
    ) -> Result<
        (PreparedInvocation, PolicyAuthorizationV2, CapabilityTokenV2),
        Box<dyn std::error::Error>,
    > {
        act(3, "Do real work under real, exact authority");
        say("The founder asks: \"validate invoice acme-2026-001\".");

        let input = serde_json::json!({
            "invoice_id": INVOICE_RESOURCE,
            "customer": "Acme Pte Ltd",
            "total_cents": 250_000
        });
        let invocation = PreparedInvocation::prepare(
            plugin.artifact(),
            selector,
            &serde_json::to_vec(&input)?,
            vec![RawResourceGrant::new("primary", INVOICE_RESOURCE)],
        )?;
        ok(&format!(
            "input passed the plugin's strict schema; resource bound: {INVOICE_RESOURCE}"
        ));
        ok(&format!(
            "canonical input digest: {}",
            short(invocation.input_digest())
        ));

        let (decision, idempotency) =
            self.decide(&invocation, DataClass::Green, AutomationLevel::L1Draft)?;
        ok("deterministic policy: allowed (green data, draft-level automation)");

        let token = self.issue(&invocation, &decision, idempotency)?;
        ok("Capability V2 issued: single use, 60 s lifetime, bound to the exact artifact,");
        say("        manifest, input, resource, and policy-decision digests");

        let result = executor.execute(VerifiedExecutionRequest {
            token: &token,
            invocation: &invocation,
            admitted: plugin,
            venture_id: VENTURE,
            subject_id: SUBJECT,
            session_id: self.session_id,
            policy_decision: &decision,
        })?;
        ok(&format!(
            "executed in the Wasmtime sandbox: zero host imports, fuel-metered \
             (guest result {}, fuel {})",
            result.exit_code, result.fuel_consumed
        ));

        let decision_hash = hash_bytes(&serde_json::to_vec(&decision)?);
        let event = ledger.append(
            AppendInput {
                venture_id: VENTURE.into(),
                actor_id: SUBJECT.into(),
                action: "execute".into(),
                resource: INVOICE_RESOURCE.into(),
                capability_id: Some(idempotency),
                payload: serde_json::json!({
                    "tool": "invoice.tools/validate",
                    "component_digest": plugin.artifact().component_digest(),
                    "input_digest": invocation.input_digest(),
                    "exit_code": result.exit_code,
                    "fuel": result.fuel_consumed,
                }),
                policy_decision_hash: Some(decision_hash),
            },
            device,
        )?;
        ledger.save(&self.root.join("ledger.json"))?;
        ledger.verify_chain()?;
        ok(&format!(
            "audit event {} appended and signed; hash chain verified",
            short_str(&event.event_hash)
        ));
        note("The guest cannot yet read the input bytes (Component/WIT ABI is future");
        note("work) — but the AUTHORIZATION of those exact bytes is fully enforced.");
        Ok((invocation, decision, token))
    }

    #[allow(clippy::too_many_arguments)]
    fn act_4_attack_gauntlet(
        &self,
        invoice_plugin: &AdmittedArtifact,
        stress_plugin: &AdmittedArtifact,
        invoice_selector: &OperationSelector,
        stress_selector: &OperationSelector,
        invocation: &PreparedInvocation,
        decision: &PolicyAuthorizationV2,
        used_token: &CapabilityTokenV2,
        executor: &mut VerifiedSandboxExecutor<CapabilityClock>,
        ledger: &AuditLedger,
        device: &DeviceIdentity,
    ) -> Result<(), Box<dyn std::error::Error>> {
        act(4, "Attack gauntlet — every attack is a real code path");

        step("1. Replay the already-used capability token:");
        match executor.execute(VerifiedExecutionRequest {
            token: used_token,
            invocation,
            admitted: invoice_plugin,
            venture_id: VENTURE,
            subject_id: SUBJECT,
            session_id: self.session_id,
            policy_decision: decision,
        }) {
            Err(SandboxError::CapabilityV2(CapabilityV2Error::Replay)) => {
                deny("denied: token already consumed (process-local replay defense)")
            }
            other => return Err(violation("token replay", &format!("{other:?}"))),
        }

        step("2. Swap the input after authorization (authorize 2,500.00 → run 99,000.00):");
        let (fresh_decision, fresh_idempotency) =
            self.decide(invocation, DataClass::Green, AutomationLevel::L1Draft)?;
        let fresh_token = self.issue(invocation, &fresh_decision, fresh_idempotency)?;
        let swapped_input = serde_json::json!({
            "invoice_id": INVOICE_RESOURCE,
            "customer": "Acme Pte Ltd",
            "total_cents": 9_900_000
        });
        let swapped = PreparedInvocation::prepare(
            invoice_plugin.artifact(),
            invoice_selector,
            &serde_json::to_vec(&swapped_input)?,
            vec![RawResourceGrant::new("primary", INVOICE_RESOURCE)],
        )?;
        match executor.execute(VerifiedExecutionRequest {
            token: &fresh_token,
            invocation: &swapped,
            admitted: invoice_plugin,
            venture_id: VENTURE,
            subject_id: SUBJECT,
            session_id: self.session_id,
            policy_decision: &fresh_decision,
        }) {
            Err(SandboxError::CapabilityV2(CapabilityV2Error::InvocationMismatch(
                "canonical_input_digest",
            ))) => deny("denied: canonical input digest mismatch — and the token was NOT consumed"),
            other => return Err(violation("input substitution", &format!("{other:?}"))),
        }
        match executor.execute(VerifiedExecutionRequest {
            token: &fresh_token,
            invocation,
            admitted: invoice_plugin,
            venture_id: VENTURE,
            subject_id: SUBJECT,
            session_id: self.session_id,
            policy_decision: &fresh_decision,
        }) {
            Ok(_) => ok("the same token still works for exactly what was authorized"),
            other => return Err(violation("authorized re-use", &format!("{other:?}"))),
        }

        step("3. A plugin manifest demands host capabilities (filesystem access):");
        let component =
            compile_wat(r#"(module (func (export "sovereign_run") (result i32) i32.const 0))"#);
        let mut greedy = invoice_manifest_json(&self.publisher, &component);
        greedy["requested_host_capabilities"] = serde_json::json!(["filesystem.read"]);
        match self.verify_plugin(&greedy, &component) {
            Err(error)
                if matches!(
                    error.downcast_ref::<ArtifactError>(),
                    Some(ArtifactError::HostCapabilitiesForbidden)
                ) =>
            {
                deny("rejected at verification: host capabilities are forbidden in this stage")
            }
            other => {
                return Err(violation(
                    "greedy manifest",
                    &format!("{:?}", other.map(|_| "verified")),
                ))
            }
        }

        step("4. A hostile plugin spins forever to burn your machine:");
        let stress_input = serde_json::json!({ "resource": "stress:demo" });
        let stress_invocation = PreparedInvocation::prepare(
            stress_plugin.artifact(),
            stress_selector,
            &serde_json::to_vec(&stress_input)?,
            vec![RawResourceGrant::new("primary", "stress:demo")],
        )?;
        let (stress_decision, stress_idempotency) = self.decide(
            &stress_invocation,
            DataClass::Green,
            AutomationLevel::L1Draft,
        )?;
        let stress_token = self.issue(&stress_invocation, &stress_decision, stress_idempotency)?;
        match executor.execute(VerifiedExecutionRequest {
            token: &stress_token,
            invocation: &stress_invocation,
            admitted: stress_plugin,
            venture_id: VENTURE,
            subject_id: SUBJECT,
            session_id: self.session_id,
            policy_decision: &stress_decision,
        }) {
            Err(SandboxError::FuelExhausted) => {
                deny("killed: fuel exhausted — and the failed attempt still consumed its token")
            }
            other => return Err(violation("infinite loop", &format!("{other:?}"))),
        }

        step("5. Prompt-injected agent tries to send red-zone data to a cloud model:");
        let blocked = self.policy.evaluate(ActionRequest {
            actor_id: "compromised_agent".into(),
            venture_id: VENTURE.into(),
            tool: "cloud.model".into(),
            operation: "infer".into(),
            resource: "customer_database".into(),
            data_class: DataClass::Red,
            automation_level: AutomationLevel::L3BoundedAuto,
        });
        if blocked.allowed {
            return Err(violation("red data to cloud", "policy allowed it"));
        }
        deny(&format!(
            "denied by deterministic policy: {}",
            blocked.reason
        ));
        note("The model can SUGGEST anything. The policy engine decides. They are");
        note("different components, and the model holds no keys.");

        step("6. Request a high-impact action (L3 automation) without human approval:");
        let (l3_decision, l3_idempotency) =
            self.decide(invocation, DataClass::Green, AutomationLevel::L3BoundedAuto)?;
        match self.issue(invocation, &l3_decision, l3_idempotency) {
            Err(error)
                if matches!(
                    error.downcast_ref::<CapabilityV2Error>(),
                    Some(CapabilityV2Error::ApprovalEvidenceUnavailable)
                ) =>
            {
                deny("fail closed: no authority is minted without approval evidence —")
            }
            other => {
                return Err(violation(
                    "approval bypass",
                    &format!("{:?}", other.map(|_| "issued")),
                ))
            }
        }
        note("the approval protocol is not built yet, so the runtime REFUSES rather");
        note("than pretending. Fail closed is the default, not the exception.");

        step("7. Tamper with the audit history (rewrite one recorded action):");
        let mut tampered_events = ledger.events().to_vec();
        if let Some(event) = tampered_events.first_mut() {
            event.action = "nothing_happened".into();
        }
        match AuditLedger::from_events(tampered_events, device.public_key_b64()) {
            Err(_) => deny("detected: signed hash chain no longer verifies"),
            Ok(_) => return Err(violation("ledger tampering", "chain verified")),
        }
        Ok(())
    }

    fn verify_plugin(
        &self,
        manifest_json: &serde_json::Value,
        component: &[u8],
    ) -> Result<(VerifiedArtifact, Vec<u8>), Box<dyn std::error::Error>> {
        let canonical = serde_json_canonicalizer::to_vec(manifest_json)?;
        let signed = self.publisher.sign_cose(&canonical)?;
        let intent = ArtifactVerificationIntent::new(
            PUBLISHER_ISSUER,
            Digest::of_bytes(&signed),
            Digest::of_bytes(component),
        )?;
        let artifact =
            ArtifactVerifier::new(&self.publishers).verify(&intent, &signed, component)?;
        Ok((artifact, signed))
    }

    fn admit(
        &self,
        artifact: &VerifiedArtifact,
    ) -> Result<AdmittedArtifact, Box<dyn std::error::Error>> {
        let store = ArtifactStore::open(self.root.join("artifacts"))?;
        match store.admit(artifact, &self.admission_signer, &ArtifactClock) {
            Ok(admitted) => Ok(admitted),
            Err(ArtifactError::AdmissionRecordExists) => {
                let admitted = store.load(
                    artifact.component_digest(),
                    artifact.manifest_digest(),
                    &self.admission_trust,
                    ADMISSION_ISSUER,
                    &ArtifactClock,
                )?;
                note("(already admitted on a previous run — reloaded from the");
                note(" content-addressed store, every digest re-verified from disk)");
                Ok(admitted)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn decide(
        &self,
        invocation: &PreparedInvocation,
        data_class: DataClass,
        automation_level: AutomationLevel,
    ) -> Result<(PolicyAuthorizationV2, Uuid), Box<dyn std::error::Error>> {
        let idempotency = Uuid::new_v4();
        let decision = self.policy.evaluate_prepared(
            invocation,
            AuthenticatedPolicyContextV2::new(
                AUDIENCE,
                VENTURE,
                SUBJECT,
                self.session_id,
                data_class,
                automation_level,
                idempotency,
            )?,
        )?;
        Ok((decision, idempotency))
    }

    fn issue(
        &self,
        invocation: &PreparedInvocation,
        decision: &PolicyAuthorizationV2,
        idempotency: Uuid,
    ) -> Result<CapabilityTokenV2, Box<dyn std::error::Error>> {
        Ok(self.issuer.issue(CapabilityV2IssueRequest {
            venture_id: VENTURE,
            subject_id: SUBJECT,
            session_id: self.session_id,
            policy_decision: decision,
            prepared_invocation: invocation,
            options: CapabilityV2IssueOptions {
                ttl: Duration::seconds(60),
                idempotency_key: idempotency,
            },
        })?)
    }

    fn pause(&self) {
        use std::io::IsTerminal;
        if self.fast || !std::io::stdin().is_terminal() {
            return;
        }
        print!("\n        [press Enter to continue]");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }
}

pub(crate) fn invoice_manifest_json(
    publisher: &TypedSigner<PublisherRole>,
    component: &[u8],
) -> serde_json::Value {
    serde_json::json!({
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
                "tool_id": "invoice.tools",
                "tool_version": "1.0.0",
                "operation_id": "validate"
            },
            "input_limits": { "max_bytes": 4096, "max_depth": 8 },
            "input_schema": {
                "type": "object",
                "properties": {
                    "invoice_id": { "type": "string", "max_utf8_bytes": 256 },
                    "customer": { "type": "string", "max_utf8_bytes": 512 },
                    "total_cents": { "type": "integer", "minimum": 0, "maximum": 100_000_000 }
                },
                "required": ["invoice_id", "customer", "total_cents"],
                "max_properties": 3
            },
            "resource_bindings": [{
                "binding_id": "primary",
                "json_pointer": "/invoice_id",
                "normalization": "exact_utf8_v1",
                "primary": true
            }]
        }]
    })
}

pub(crate) fn stress_manifest_json(
    publisher: &TypedSigner<PublisherRole>,
    component: &[u8],
) -> serde_json::Value {
    serde_json::json!({
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
                "tool_id": "demo.stress",
                "tool_version": "1.0.0",
                "operation_id": "spin"
            },
            "input_limits": { "max_bytes": 1024, "max_depth": 4 },
            "input_schema": {
                "type": "object",
                "properties": {
                    "resource": { "type": "string", "max_utf8_bytes": 256 }
                },
                "required": ["resource"],
                "max_properties": 1
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

pub(crate) fn compile_wat(source: &str) -> Vec<u8> {
    wat::parse_str(source).expect("demo Wasm fixtures are valid WAT")
}

fn banner() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║        SOVEREIGN FOUNDER OS · Stage 1 Secure Kernel Demo          ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Every ✓ and ✗ below is a real enforcement path: real signatures,");
    println!("  real policy decisions, real Wasm execution, real audit evidence.");
    println!("  Demo keys are hard-coded and grant nothing outside this demo.");
}

fn act_5_takeaway() {
    act(5, "What just happened");
    println!("  Your data stayed local and encrypted. A plugin ran only after its");
    println!("  publisher was verified AND your own key admitted it. Every execution");
    println!("  needed a one-use capability bound to the exact code and input. Every");
    println!("  attack was denied by a boundary, not by good intentions — and the");
    println!("  denials themselves are reproducible code paths you can read.");
    println!();
    println!("  Honest limits of this stage (also in ARCHITECTURE.md):");
    println!("  · replay defense is process-local (durable Authority Store pending)");
    println!("  · the guest does not yet receive input bytes (WIT ABI pending)");
    println!("  · no external effects exist yet — effectful requests fail closed");
    println!("  · demo trust anchors are ephemeral, not production key management");
    println!();
    println!("  Kill the model, the server, and the plugin.");
    println!("  The company keeps running. That is the product we are building.");
}

fn act(number: u8, title: &str) {
    println!();
    println!("──────────────────────────────────────────────────────────────────────");
    println!(" ACT {number} · {title}");
    println!("──────────────────────────────────────────────────────────────────────");
}

fn say(text: &str) {
    println!("  {text}");
}

fn step(text: &str) {
    println!();
    println!("  {text}");
}

fn ok(text: &str) {
    println!("  ✓ {text}");
}

fn deny(text: &str) {
    println!("  ✗ {text}");
}

fn note(text: &str) {
    println!("    {text}");
}

fn short(digest: Digest) -> String {
    short_str(&digest.as_hex())
}

fn short_str(hex: &str) -> String {
    format!("{}…", &hex[..12.min(hex.len())])
}

/// A gauntlet step that does not fail the way the kernel promises is a demo
/// bug or a regression; refuse to print a success story over it.
fn violation(attack: &str, outcome: &str) -> Box<dyn std::error::Error> {
    format!(
        "SECURITY EXPECTATION VIOLATED in demo: attack `{attack}` produced unexpected \
         outcome: {outcome}. This is a bug — please report it."
    )
    .into()
}
