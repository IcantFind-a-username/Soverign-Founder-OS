use clap::{Parser, Subcommand};
use sovereign_audit_ledger::{hash_bytes, AppendInput, AuditLedger};
use sovereign_capability::{CapabilityIssuer, IssueOptions};
use sovereign_contracts::{ActionRequest, AutomationLevel, DataClass};
use sovereign_identity::DeviceIdentity;
use sovereign_policy::PolicyEngine;
use sovereign_sandbox::{ExecutionRequest, SandboxExecutor, WasmExecutionRequest};
use sovereign_vault::Vault;
use std::path::PathBuf;

// Equivalent WAT:
// (module (func (export "sovereign_run") (result i32) i32.const 7))
// Keeping this tiny fixture as bytes avoids shipping a text-to-Wasm compiler in the CLI.
const SANDBOX_CHECK_MODULE: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, 0x03,
    0x02, 0x01, 0x00, 0x07, 0x11, 0x01, 0x0d, 0x73, 0x6f, 0x76, 0x65, 0x72, 0x65, 0x69, 0x67, 0x6e,
    0x5f, 0x72, 0x75, 0x6e, 0x00, 0x00, 0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x07, 0x0b,
];

#[derive(Parser)]
#[command(name = "sovereign", about = "Sovereign Runtime CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize local device identity, vault, and ledger
    Init,
    /// Run the secure kernel demo workflow (effectful tools remain simulated)
    Demo,
    /// Run a mechanical check of the import-free Phase A Wasmtime path
    SandboxCheck,
    /// Show vault entry names
    Status,
}

fn data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("sovereign-founder-os")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init => cmd_init()?,
        Commands::Demo => cmd_demo()?,
        Commands::SandboxCheck => cmd_sandbox_check()?,
        Commands::Status => cmd_status()?,
    }
    Ok(())
}

fn cmd_sandbox_check() -> Result<(), Box<dyn std::error::Error>> {
    let policy = PolicyEngine::new();
    let decision = policy.evaluate(ActionRequest {
        actor_id: "runtime_self_check".into(),
        venture_id: "system".into(),
        tool: "sandbox".into(),
        operation: "runtime_check".into(),
        resource: "runtime:wasmtime".into(),
        data_class: DataClass::Green,
        automation_level: AutomationLevel::L1Draft,
    });
    let issuer = CapabilityIssuer::new();
    let token = issuer.issue(&decision, IssueOptions::default(), false)?;
    let mut sandbox = SandboxExecutor::new(
        vec!["sandbox.runtime_check".into()],
        issuer.public_key_b64(),
    )?;
    let result = sandbox.execute_wasm(WasmExecutionRequest {
        token: &token,
        venture_id: "system",
        actor_id: "runtime_self_check",
        tool: "sandbox",
        operation: "runtime_check",
        resource: "runtime:wasmtime",
        module: SANDBOX_CHECK_MODULE,
    })?;

    if result.exit_code != 7 || !result.runtime.is_isolated() {
        return Err("isolated runtime self-check returned an unexpected result".into());
    }

    println!("self-check capability validation: OK");
    println!("authority: ephemeral self-check issuer (not a production trust anchor)");
    println!("runtime: {}", result.runtime.as_str());
    println!(
        "guest Wasm boundary active: {}",
        result.runtime.is_isolated()
    );
    println!(
        "production ready: {} (artifact binding and durable audit are pending)",
        result.runtime.is_production_ready()
    );
    println!("host import policy: deny all");
    println!("fuel consumed: {}", result.fuel_consumed);
    println!("guest result: {}", result.exit_code);
    Ok(())
}

fn cmd_init() -> Result<(), Box<dyn std::error::Error>> {
    let root = data_dir();
    std::fs::create_dir_all(&root)?;

    let device_path = root.join("device.json");
    if !device_path.exists() {
        let device = DeviceIdentity::generate();
        device.save(&device_path)?;
        println!("device identity: {}", device.device_id());
    } else {
        let device = DeviceIdentity::load(&device_path)?;
        println!("device identity: {} (existing)", device.device_id());
    }

    let vault = Vault::init(root.join("vault"))?;
    println!("vault ready: {} entries", vault.list().len());

    let ledger_path = root.join("ledger.json");
    if !ledger_path.exists() {
        let ledger = AuditLedger::new();
        ledger.save(&ledger_path)?;
    }
    println!("ledger ready: {}", ledger_path.display());
    println!("data directory: {}", root.display());
    Ok(())
}

fn cmd_status() -> Result<(), Box<dyn std::error::Error>> {
    let root = data_dir();
    let vault = Vault::init(root.join("vault"))?;
    println!("vault entries:");
    for name in vault.list() {
        println!("  - {name}");
    }
    let ledger_path = root.join("ledger.json");
    if ledger_path.exists() {
        let device = DeviceIdentity::load(&root.join("device.json"))?;
        let ledger = AuditLedger::load(&ledger_path, device.public_key_b64())?;
        println!("audit events: {}", ledger.events().len());
    }
    Ok(())
}

fn cmd_demo() -> Result<(), Box<dyn std::error::Error>> {
    let root = data_dir();
    std::fs::create_dir_all(&root)?;

    let device_path = root.join("device.json");
    let device = if device_path.exists() {
        DeviceIdentity::load(&device_path)?
    } else {
        let d = DeviceIdentity::generate();
        d.save(&device_path)?;
        d
    };

    let mut vault = Vault::init(root.join("vault"))?;
    vault.put(
        "venture_profile",
        br#"{"name":"Acme Consulting","stage":"customer_validation"}"#,
    )?;

    let policy = PolicyEngine::new();
    let request = ActionRequest {
        actor_id: "agent_builder".into(),
        venture_id: "ven_demo".into(),
        tool: "email".into(),
        operation: "draft".into(),
        resource: "customer:acme".into(),
        data_class: DataClass::Amber,
        automation_level: AutomationLevel::L1Draft,
    };

    println!("\n== Policy evaluation ==");
    let decision = policy.evaluate(request);
    println!("allowed: {}", decision.allowed);
    println!("requires_approval: {}", decision.requires_approval);
    println!("reason: {}", decision.reason);

    let issuer = CapabilityIssuer::new();
    let token = issuer.issue(&decision, IssueOptions::default(), false)?;
    println!("\n== Capability token issued ==");
    println!("token_id: {}", token.token_id);
    println!("expires_at: {}", token.expires_at);

    let mut sandbox = SandboxExecutor::new(vec!["email.draft".into()], issuer.public_key_b64())?;
    let result = sandbox.execute_simulated(ExecutionRequest {
        token: &token,
        venture_id: "ven_demo",
        actor_id: "agent_builder",
        tool: "email",
        operation: "draft",
        resource: "customer:acme",
        input: serde_json::json!({"subject": "Proposal for Acme Ltd."}),
    })?;
    println!("\n== Simulated execution (not isolated) ==");
    println!("{}", serde_json::to_string_pretty(&result.output)?);

    let decision_hash = hash_bytes(&serde_json::to_vec(&decision)?);
    let ledger_path = root.join("ledger.json");
    let mut ledger = if ledger_path.exists() {
        AuditLedger::load(&ledger_path, device.public_key_b64())?
    } else {
        AuditLedger::new()
    };

    let event = ledger.append(
        AppendInput {
            venture_id: "ven_demo".into(),
            actor_id: "agent_builder".into(),
            action: "execute".into(),
            resource: "email:draft".into(),
            capability_id: Some(token.token_id),
            payload: result.output,
            policy_decision_hash: Some(decision_hash),
        },
        &device,
    )?;
    ledger.save(&ledger_path)?;

    println!("\n== Audit event recorded ==");
    println!("event_id: {}", event.event_id);
    println!("event_hash: {}", event.event_hash);
    ledger.verify_chain()?;
    println!("chain integrity: OK");

    // Demonstrate policy block
    println!("\n== Adversarial check: red data to cloud ==");
    let blocked = policy.evaluate(ActionRequest {
        actor_id: "malicious_agent".into(),
        venture_id: "ven_demo".into(),
        tool: "cloud.model".into(),
        operation: "infer".into(),
        resource: "customer_database".into(),
        data_class: DataClass::Red,
        automation_level: AutomationLevel::L3BoundedAuto,
    });
    println!("allowed: {} — {}", blocked.allowed, blocked.reason);

    println!("\nDemo complete. Company data remains local and encrypted.");
    Ok(())
}
