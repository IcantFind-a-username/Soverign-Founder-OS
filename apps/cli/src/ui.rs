//! Local Security Center: a read-only dashboard over the real kernel state
//! plus an in-memory attack gauntlet, served on loopback only.
//!
//! Trust posture, stated explicitly:
//! - binds 127.0.0.1 only; this is a single-user local preview, not a hosted
//!   service, and it has no authentication because it never leaves the device;
//! - GET endpoints expose no secrets: vault entry *names* only, digests, and
//!   admission-record claims — never vault plaintext or private keys;
//! - the gauntlet runs entirely in memory with the hard-coded demo trust
//!   anchors; it performs no external effects and touches no stored state;
//! - this page hosts an early Founder Command Center: a read-only, at-a-glance
//!   view of the business joined with the kernel evidence that backs it.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use chrono::Duration;
use sovereign_artifact::{
    AdmissionRecordClaimsV1, ArtifactError, ArtifactVerificationIntent, ArtifactVerifier, Digest,
    OperationSelector, PreparedInvocation, RawResourceGrant, VerifiedArtifact,
    HARD_MAX_SIGNED_ADMISSION_BYTES,
};
use sovereign_audit_ledger::{AppendInput, AuditLedger};
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
use tiny_http::{Header, Method, Response, Server};
use uuid::Uuid;

use crate::demo;
use crate::workspace;

const UI_HTML: &str = include_str!("../assets/ui.html");

const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

pub fn run(port: u16, root: PathBuf, open_browser: bool) -> Result<(), Box<dyn std::error::Error>> {
    let server = Server::http(("127.0.0.1", port))
        .map_err(|error| format!("cannot bind 127.0.0.1:{port}: {error}"))?;
    let url = format!("http://127.0.0.1:{port}");
    println!("Sovereign Founder OS · local app");
    println!("  {url}");
    println!("  loopback only · encrypted local state · Ctrl-C to stop");
    if open_browser {
        launch_browser(&url);
    }

    for mut request in server.incoming_requests() {
        let response = route(&mut request, port, &root);
        let _ = request.respond(response);
    }
    Ok(())
}

/// Best-effort convenience only: a failure to open a browser is silent and
/// harmless; the printed URL remains the source of truth.
fn launch_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = std::process::Command::new("open");
        command.arg(url);
        command
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = std::process::Command::new("cmd");
        command.args(["/C", "start", "", url]);
        command
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut command = std::process::Command::new("xdg-open");
        command.arg(url);
        command
    };
    let _ = command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

type UiResponse = Response<std::io::Cursor<Vec<u8>>>;

fn route(request: &mut tiny_http::Request, port: u16, root: &Path) -> UiResponse {
    // DNS-rebinding defense: a browser lured to attacker.example resolving to
    // 127.0.0.1 still sends the attacker's Host header; refuse it.
    if !host_allowed(request, port) {
        return json_response(&serde_json::json!({ "ok": false, "error": "forbidden host" }))
            .with_status_code(403);
    }
    let url = request.url().to_owned();
    match (request.method().clone(), url.as_str()) {
        (Method::Get, "/") => html_response(UI_HTML),
        (Method::Get, "/api/state") => json_response(&state_json(root)),
        (Method::Get, "/api/command-center") => json_response(&command_center_json(root)),
        (Method::Get, "/api/workspace") => json_response(&workspace_get(root)),
        (Method::Get, "/api/export") => export_response(root),
        (Method::Post, "/api/gauntlet") => match read_json_body(request) {
            Ok(_) => json_response(&gauntlet_json()),
            Err(error) => bad_request(&error),
        },
        (Method::Post, "/api/workspace/assist") => match read_json_body(request) {
            Ok(body) => json_response(&workspace_assist(&body, root)),
            Err(error) => bad_request(&error),
        },
        (Method::Post, "/api/verify-export") => match read_json_body(request) {
            Ok(body) => json_response(&verify_export_json(&body)),
            Err(error) => bad_request(&error),
        },
        (Method::Post, path) if path.starts_with("/api/workspace/") => {
            match read_json_body(request) {
                Ok(body) => json_response(&workspace_post(path, &body, root)),
                Err(error) => bad_request(&error),
            }
        }
        _ => Response::from_string("not found").with_status_code(404),
    }
}

fn host_allowed(request: &tiny_http::Request, port: u16) -> bool {
    let allowed = [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        "127.0.0.1".to_owned(),
        "localhost".to_owned(),
    ];
    request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Host"))
        .map(|header| {
            let value = header.value.as_str();
            allowed.iter().any(|candidate| candidate == value)
        })
        .unwrap_or(false)
}

/// Read a JSON request body. Requiring `Content-Type: application/json` is a
/// CSRF defense: cross-origin pages cannot send that content type without a
/// CORS preflight, which this server never approves.
fn read_json_body(request: &mut tiny_http::Request) -> Result<serde_json::Value, String> {
    let is_json = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Content-Type"))
        .map(|header| {
            header
                .value
                .as_str()
                .to_ascii_lowercase()
                .starts_with("application/json")
        })
        .unwrap_or(false);
    if !is_json {
        return Err("Content-Type must be application/json".into());
    }
    let mut body = Vec::new();
    std::io::Read::take(request.as_reader(), (MAX_REQUEST_BODY_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    if body.len() > MAX_REQUEST_BODY_BYTES {
        return Err("request body too large".into());
    }
    if body.is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_slice(&body).map_err(|error| format!("invalid JSON body: {error}"))
}

fn bad_request(message: &str) -> UiResponse {
    json_response(&serde_json::json!({ "ok": false, "error": message })).with_status_code(400)
}

fn workspace_get(root: &Path) -> serde_json::Value {
    let result = workspace::Store::open(root).and_then(|store| store.load());
    match result {
        Ok(state) => serde_json::json!({ "ok": true, "workspace": state }),
        Err(error) => serde_json::json!({ "ok": false, "error": error.to_string() }),
    }
}

/// The Founder Command Center: the business at a glance joined with the kernel
/// evidence that backs it. Read-only; it composes two honest sources — the
/// workspace aggregation and the on-disk audit signals — and invents nothing.
fn command_center_json(root: &Path) -> serde_json::Value {
    let result = workspace::Store::open(root).and_then(|store| store.command_center());
    match result {
        Ok(summary) => serde_json::json!({
            "ok": true,
            "summary": summary,
            "kernel": kernel_evidence_json(root),
        }),
        Err(error) => serde_json::json!({ "ok": false, "error": error.to_string() }),
    }
}

/// Compact, verifiable kernel signals for the Command Center header: the audit
/// chain's health, how many model disclosures happened, and how many plugins
/// were admitted. Every number here is re-derivable from the export.
fn kernel_evidence_json(root: &Path) -> serde_json::Value {
    let device = DeviceIdentity::load(&root.join("device.json")).ok();
    let ledger_path = root.join("ledger.json");
    let (present, chain_ok, count, model_disclosures) = match (&device, ledger_path.exists()) {
        (Some(device), true) => match AuditLedger::load(&ledger_path, device.public_key_b64()) {
            Ok(ledger) => {
                let disclosures = ledger
                    .events()
                    .iter()
                    .filter(|event| event.action == "model.drafted")
                    .count();
                let chain_ok = ledger.verify_chain().is_ok();
                (true, chain_ok, ledger.events().len(), disclosures)
            }
            Err(_) => (true, false, 0, 0),
        },
        _ => (false, true, 0, 0),
    };
    serde_json::json!({
        "audit_chain_present": present,
        "audit_chain_ok": chain_ok,
        "audit_events": count,
        "model_disclosures": model_disclosures,
        "admitted_plugins": admitted_plugins_json(root).len(),
    })
}

fn workspace_post(path: &str, body: &serde_json::Value, root: &Path) -> serde_json::Value {
    let result = (|| {
        let store = workspace::Store::open(root)?;
        match path {
            "/api/workspace/venture" => {
                store.set_venture(str_field(body, "name")?, str_field(body, "service")?)
            }
            "/api/workspace/customer" => store.add_customer(
                str_field(body, "name")?,
                body.get("email").and_then(|v| v.as_str()).unwrap_or(""),
                body.get("notes").and_then(|v| v.as_str()).unwrap_or(""),
            ),
            "/api/workspace/offer" => store.create_document(
                workspace::DocumentKind::Offer,
                uuid_field(body, "customer_id")?,
                None,
                lang_field(body),
            ),
            "/api/workspace/invoice" => store.create_document(
                workspace::DocumentKind::Invoice,
                uuid_field(body, "customer_id")?,
                Some(workspace::parse_amount_cents(str_field(body, "amount")?)?),
                lang_field(body),
            ),
            "/api/workspace/request-send" => store.request_send(uuid_field(body, "document_id")?),
            "/api/workspace/decide" => store.decide(
                uuid_field(body, "approval_id")?,
                body.get("approve")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            ),
            _ => Err(workspace::WorkspaceError::NotFound("route".into())),
        }
    })();
    match result {
        Ok(state) => serde_json::json!({ "ok": true, "workspace": state }),
        Err(error) => serde_json::json!({ "ok": false, "error": error.to_string() }),
    }
}

fn workspace_assist(body: &serde_json::Value, root: &Path) -> serde_json::Value {
    let result = (|| {
        let store = workspace::Store::open(root)?;
        store.draft_assistant(uuid_field(body, "customer_id")?, lang_field(body))
    })();
    match result {
        Ok(suggestion) => serde_json::json!({ "ok": true, "suggestion": suggestion }),
        Err(error) => serde_json::json!({ "ok": false, "error": error.to_string() }),
    }
}

/// Verify a bundle the user pasted or loaded in the browser. Pure: it opens no
/// store and needs no device, so it also works for a backup made on another
/// machine. The `bundle` is the exported JSON, nested under a `bundle` key.
fn verify_export_json(body: &serde_json::Value) -> serde_json::Value {
    let bundle = match body.get("bundle") {
        Some(bundle) if !bundle.is_null() => bundle,
        _ => return serde_json::json!({ "ok": false, "error": "no bundle provided" }),
    };
    match workspace::verify_export(bundle) {
        Ok(report) => serde_json::json!({ "ok": true, "report": report }),
        Err(error) => serde_json::json!({ "ok": false, "error": error.to_string() }),
    }
}

fn export_response(root: &Path) -> UiResponse {
    let export = workspace::Store::open(root).and_then(|store| store.export());
    match export {
        Ok(bundle) => {
            let pretty =
                serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| bundle.to_string());
            Response::from_string(pretty)
                .with_header(
                    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                        .expect("static header"),
                )
                .with_header(
                    Header::from_bytes(
                        &b"Content-Disposition"[..],
                        &b"attachment; filename=\"sovereign-export.json\""[..],
                    )
                    .expect("static header"),
                )
        }
        Err(error) => {
            json_response(&serde_json::json!({ "ok": false, "error": error.to_string() }))
                .with_status_code(500)
        }
    }
}

fn str_field<'a>(
    body: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, workspace::WorkspaceError> {
    body.get(field)
        .and_then(|value| value.as_str())
        .ok_or_else(|| workspace::WorkspaceError::Invalid(format!("{field} is required")))
}

fn uuid_field(body: &serde_json::Value, field: &str) -> Result<Uuid, workspace::WorkspaceError> {
    str_field(body, field)?
        .parse()
        .map_err(|_| workspace::WorkspaceError::Invalid(format!("{field} must be a UUID")))
}

fn lang_field(body: &serde_json::Value) -> &str {
    match body.get("lang").and_then(|value| value.as_str()) {
        Some(lang) if lang.starts_with("zh") => "zh",
        _ => "en",
    }
}

fn html_response(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body).with_header(
        Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
            .expect("static header"),
    )
}

fn json_response(value: &serde_json::Value) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(value.to_string()).with_header(
        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("static header"),
    )
}

// ---------------------------------------------------------------------------
// GET /api/state — real on-disk kernel state, no secrets
// ---------------------------------------------------------------------------

fn state_json(root: &Path) -> serde_json::Value {
    let device = DeviceIdentity::load(&root.join("device.json")).ok();
    let device_id = device.as_ref().map(|d| d.device_id().to_owned());

    let vault_entries: Vec<String> = sovereign_vault::Vault::init(root.join("vault"))
        .map(|vault| vault.list().to_vec())
        .unwrap_or_default();

    let ledger_path = root.join("ledger.json");
    let ledger = match (&device, ledger_path.exists()) {
        (Some(device), true) => match AuditLedger::load(&ledger_path, device.public_key_b64()) {
            Ok(ledger) => {
                let events: Vec<serde_json::Value> = ledger
                    .events()
                    .iter()
                    .rev()
                    .take(25)
                    .map(|event| {
                        serde_json::json!({
                            "timestamp": event.timestamp.to_rfc3339(),
                            "actor": event.actor_id,
                            "action": event.action,
                            "resource": event.resource,
                            "hash": &event.event_hash[..12],
                        })
                    })
                    .collect();
                serde_json::json!({
                    "present": true,
                    "chain_ok": true,
                    "count": ledger.events().len(),
                    "events": events,
                })
            }
            Err(error) => serde_json::json!({
                "present": true,
                "chain_ok": false,
                "count": 0,
                "events": [],
                "error": error.to_string(),
            }),
        },
        _ => serde_json::json!({ "present": false, "chain_ok": false, "count": 0, "events": [] }),
    };

    serde_json::json!({
        "device_id": device_id,
        "vault_entries": vault_entries,
        "ledger": ledger,
        "plugins": admitted_plugins_json(root),
        "stage": "Stage 1 · Secure Kernel · Founder Command Center (early)",
    })
}

/// List admission records from the on-disk store, verifying each record
/// against the demo admission trust anchor. A record that fails verification
/// is still listed — flagged unverified — because showing a tampered record
/// as "absent" would hide evidence from the owner.
fn admitted_plugins_json(root: &Path) -> Vec<serde_json::Value> {
    let admissions_dir = root.join("artifacts").join("admissions");
    let Ok(entries) = std::fs::read_dir(&admissions_dir) else {
        return Vec::new();
    };
    let trust = demo_admission_trust();
    let now_unix = chrono::Utc::now().timestamp();

    let mut plugins = Vec::new();
    let mut names: Vec<_> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit()))
        .collect();
    names.sort();
    for name in names {
        let path = admissions_dir.join(&name);
        let record = std::fs::metadata(&path)
            .ok()
            .filter(|metadata| {
                metadata.is_file() && metadata.len() <= HARD_MAX_SIGNED_ADMISSION_BYTES as u64
            })
            .and_then(|_| std::fs::read(&path).ok());
        let Some(record) = record else {
            continue;
        };
        match trust
            .verify(&record, demo::ADMISSION_ISSUER, now_unix)
            .ok()
            .and_then(|verified| {
                serde_json::from_slice::<AdmissionRecordClaimsV1>(verified.payload()).ok()
            }) {
            Some(claims) => plugins.push(serde_json::json!({
                "verified": true,
                "admission_id": claims.admission_id,
                "component_digest": &claims.component_digest.as_hex()[..12],
                "manifest_digest": &claims.manifest_digest.as_hex()[..12],
                "risk_class": claims.risk_class,
                "backend": claims.backend,
                "state": claims.installation_state,
                "admitted_at_unix": claims.admitted_at_unix,
                "issuer": claims.admitting_issuer,
            })),
            None => plugins.push(serde_json::json!({
                "verified": false,
                "manifest_digest": &name[..12],
                "error": "admission record failed verification against the demo trust anchor",
            })),
        }
    }
    plugins
}

fn demo_admission_trust() -> RoleTrustStore<AdmissionRole> {
    let now_unix = chrono::Utc::now().timestamp();
    let mut trust = RoleTrustStore::<AdmissionRole>::new();
    if let Ok(signer) = TypedSigner::<AdmissionRole>::from_secret_bytes(
        demo::ADMISSION_ISSUER,
        demo::DEMO_ADMISSION_SECRET,
    ) {
        if let Ok(validity) = KeyValidity::new(now_unix - 60, now_unix + 3_600) {
            let _ = trust.trust_signer(&signer, validity);
        }
    }
    trust
}

// ---------------------------------------------------------------------------
// POST /api/gauntlet — the seven attacks, entirely in memory
// ---------------------------------------------------------------------------

struct Gauntlet {
    publisher: TypedSigner<PublisherRole>,
    publishers: RoleTrustStore<PublisherRole>,
    issuer: CapabilityIssuerV2<CapabilityClock>,
    policy: PolicyEngine,
    session_id: Uuid,
}

fn gauntlet_json() -> serde_json::Value {
    match run_gauntlet() {
        Ok(results) => serde_json::json!({ "ok": true, "results": results }),
        Err(error) => serde_json::json!({ "ok": false, "error": error.to_string() }),
    }
}

fn check(results: &mut Vec<serde_json::Value>, key: &str, name: &str, pass: bool, detail: &str) {
    results.push(serde_json::json!({ "key": key, "name": name, "pass": pass, "detail": detail }));
}

fn run_gauntlet() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let now_unix = chrono::Utc::now().timestamp();
    let validity = KeyValidity::new(now_unix - 60, now_unix + 3_600)?;

    let publisher = TypedSigner::<PublisherRole>::from_secret_bytes(
        demo::PUBLISHER_ISSUER,
        demo::DEMO_PUBLISHER_SECRET,
    )?;
    let mut publishers = RoleTrustStore::<PublisherRole>::new();
    publishers.trust_signer(&publisher, validity)?;

    let authority = TypedSigner::<AuthorityRole>::from_secret_bytes(
        demo::AUTHORITY_ISSUER,
        demo::DEMO_AUTHORITY_SECRET,
    )?;
    let mut authority_trust = RoleTrustStore::<AuthorityRole>::new();
    authority_trust.trust_signer(&authority, validity)?;
    let issuer = CapabilityIssuerV2::new(authority, demo::AUDIENCE, CapabilityClock)?;
    let validator = CapabilityValidatorV2::new(
        authority_trust,
        demo::AUTHORITY_ISSUER,
        demo::AUDIENCE,
        CapabilityClock,
    )?;

    let gauntlet = Gauntlet {
        publisher,
        publishers,
        issuer,
        policy: PolicyEngine::new(),
        session_id: Uuid::new_v4(),
    };

    let invoice_selector = OperationSelector::new("invoice.tools", "1.0.0", "validate")?;
    let stress_selector = OperationSelector::new("demo.stress", "1.0.0", "spin")?;
    let mut executor = VerifiedSandboxExecutor::new(
        vec![invoice_selector.clone(), stress_selector.clone()],
        validator,
    )?;

    let invoice_component =
        demo::compile_wat(r#"(module (func (export "sovereign_run") (result i32) i32.const 0))"#);
    let invoice_artifact = gauntlet.verify(
        &demo::invoice_manifest_json(&gauntlet.publisher, &invoice_component),
        &invoice_component,
    )?;
    let invocation = prepare_invoice(&invoice_artifact, 250_000)?;
    let (decision, idempotency) = gauntlet.decide(&invocation, AutomationLevel::L1Draft)?;
    let token = gauntlet.issue(&invocation, &decision, idempotency)?;

    let mut results = Vec::new();

    let baseline = executor.execute(gauntlet.request(&token, &invocation, &decision));
    check(
        &mut results,
        "baseline",
        "Baseline: authorized execution",
        baseline.is_ok(),
        "signed plugin ran in the import-free Wasmtime sandbox under an exact one-use capability",
    );

    let replay = executor.execute(gauntlet.request(&token, &invocation, &decision));
    check(
        &mut results,
        "replay",
        "Token replay",
        matches!(
            replay,
            Err(SandboxError::CapabilityV2(CapabilityV2Error::Replay))
        ),
        "re-presenting the consumed capability was denied (process-local replay defense)",
    );

    let (fresh_decision, fresh_idempotency) =
        gauntlet.decide(&invocation, AutomationLevel::L1Draft)?;
    let fresh_token = gauntlet.issue(&invocation, &fresh_decision, fresh_idempotency)?;
    let swapped = prepare_invoice(&invoice_artifact, 9_900_000)?;
    let substitution = executor.execute(gauntlet.request(&fresh_token, &swapped, &fresh_decision));
    let substitution_denied = matches!(
        substitution,
        Err(SandboxError::CapabilityV2(
            CapabilityV2Error::InvocationMismatch("canonical_input_digest")
        ))
    );
    let honest_reuse = executor
        .execute(gauntlet.request(&fresh_token, &invocation, &fresh_decision))
        .is_ok();
    check(
        &mut results,
        "substitution",
        "Input substitution after authorization",
        substitution_denied && honest_reuse,
        "swapped input was denied by digest mismatch; the untouched token still ran the authorized input",
    );

    let mut greedy = demo::invoice_manifest_json(&gauntlet.publisher, &invoice_component);
    greedy["requested_host_capabilities"] = serde_json::json!(["filesystem.read"]);
    let greedy_result = gauntlet.verify(&greedy, &invoice_component);
    check(
        &mut results,
        "greedy_manifest",
        "Manifest demands host capabilities",
        matches!(greedy_result, Err(ArtifactError::HostCapabilitiesForbidden)),
        "a manifest requesting filesystem access was rejected before any code ran",
    );

    let stress_component = demo::compile_wat(
        r#"(module
            (func (export "sovereign_run") (result i32)
                (loop $forever i32.const 1 drop br $forever)
                unreachable))"#,
    );
    let stress_artifact = gauntlet.verify(
        &demo::stress_manifest_json(&gauntlet.publisher, &stress_component),
        &stress_component,
    )?;
    let stress_input = serde_json::json!({ "resource": "stress:demo" });
    let stress_invocation = PreparedInvocation::prepare(
        &stress_artifact,
        &stress_selector,
        &serde_json::to_vec(&stress_input)?,
        vec![RawResourceGrant::new("primary", "stress:demo")],
    )?;
    let (stress_decision, stress_idempotency) =
        gauntlet.decide(&stress_invocation, AutomationLevel::L1Draft)?;
    let stress_token = gauntlet.issue(&stress_invocation, &stress_decision, stress_idempotency)?;
    let loop_result =
        executor.execute(gauntlet.request(&stress_token, &stress_invocation, &stress_decision));
    check(
        &mut results,
        "infinite_loop",
        "Infinite-loop plugin",
        matches!(loop_result, Err(SandboxError::FuelExhausted)),
        "runaway guest was killed by deterministic fuel metering; the attempt still consumed its token",
    );

    let red = gauntlet.policy.evaluate(ActionRequest {
        actor_id: "compromised_agent".into(),
        venture_id: demo::VENTURE.into(),
        tool: "cloud.model".into(),
        operation: "infer".into(),
        resource: "customer_database".into(),
        data_class: DataClass::Red,
        automation_level: AutomationLevel::L3BoundedAuto,
    });
    check(
        &mut results,
        "red_cloud",
        "Red-zone data to a cloud model",
        !red.allowed,
        &format!("deterministic policy denial: {}", red.reason),
    );

    let (l3_decision, l3_idempotency) =
        gauntlet.decide(&invocation, AutomationLevel::L3BoundedAuto)?;
    let approval = gauntlet.issue(&invocation, &l3_decision, l3_idempotency);
    check(
        &mut results,
        "approval",
        "High-impact action without human approval",
        matches!(
            approval,
            Err(CapabilityV2Error::ApprovalEvidenceUnavailable)
        ),
        "no capability is minted without approval evidence — the runtime fails closed",
    );

    let device = DeviceIdentity::generate();
    let mut ledger = AuditLedger::new();
    ledger.append(
        AppendInput {
            venture_id: demo::VENTURE.into(),
            actor_id: demo::SUBJECT.into(),
            action: "execute".into(),
            resource: demo::INVOICE_RESOURCE.into(),
            capability_id: None,
            payload: serde_json::json!({ "gauntlet": true }),
            policy_decision_hash: None,
        },
        &device,
    )?;
    let mut tampered_events = ledger.events().to_vec();
    tampered_events[0].action = "nothing_happened".into();
    let tamper_detected =
        AuditLedger::from_events(tampered_events, device.public_key_b64()).is_err();
    check(
        &mut results,
        "audit_tamper",
        "Audit history tampering",
        tamper_detected,
        "rewriting one recorded action broke the signed hash chain and was detected",
    );

    Ok(results)
}

impl Gauntlet {
    fn verify(
        &self,
        manifest_json: &serde_json::Value,
        component: &[u8],
    ) -> Result<VerifiedArtifact, ArtifactError> {
        let canonical = serde_json_canonicalizer::to_vec(manifest_json)
            .map_err(|_| ArtifactError::InputCanonicalizationFailed)?;
        let signed = self
            .publisher
            .sign_cose(&canonical)
            .map_err(|_| ArtifactError::PublisherVerificationFailed)?;
        let intent = ArtifactVerificationIntent::new(
            demo::PUBLISHER_ISSUER,
            Digest::of_bytes(&signed),
            Digest::of_bytes(component),
        )?;
        ArtifactVerifier::new(&self.publishers).verify(&intent, &signed, component)
    }

    fn decide(
        &self,
        invocation: &PreparedInvocation,
        automation_level: AutomationLevel,
    ) -> Result<(PolicyAuthorizationV2, Uuid), Box<dyn std::error::Error>> {
        let idempotency = Uuid::new_v4();
        let decision = self.policy.evaluate_prepared(
            invocation,
            AuthenticatedPolicyContextV2::new(
                demo::AUDIENCE,
                demo::VENTURE,
                demo::SUBJECT,
                self.session_id,
                DataClass::Green,
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
    ) -> Result<CapabilityTokenV2, CapabilityV2Error> {
        self.issuer.issue(CapabilityV2IssueRequest {
            venture_id: demo::VENTURE,
            subject_id: demo::SUBJECT,
            session_id: self.session_id,
            policy_decision: decision,
            prepared_invocation: invocation,
            options: CapabilityV2IssueOptions {
                ttl: Duration::seconds(60),
                idempotency_key: idempotency,
            },
        })
    }

    fn request<'a>(
        &self,
        token: &'a CapabilityTokenV2,
        invocation: &'a PreparedInvocation,
        decision: &'a PolicyAuthorizationV2,
    ) -> VerifiedExecutionRequest<'a> {
        VerifiedExecutionRequest {
            token,
            invocation,
            venture_id: demo::VENTURE,
            subject_id: demo::SUBJECT,
            session_id: self.session_id,
            policy_decision: decision,
        }
    }
}

fn prepare_invoice(
    artifact: &VerifiedArtifact,
    total_cents: i64,
) -> Result<PreparedInvocation, ArtifactError> {
    let input = serde_json::json!({
        "invoice_id": demo::INVOICE_RESOURCE,
        "customer": "Acme Pte Ltd",
        "total_cents": total_cents
    });
    PreparedInvocation::prepare(
        artifact,
        &OperationSelector::new("invoice.tools", "1.0.0", "validate")?,
        &serde_json::to_vec(&input).expect("static demo input serializes"),
        vec![RawResourceGrant::new("primary", demo::INVOICE_RESOURCE)],
    )
}
