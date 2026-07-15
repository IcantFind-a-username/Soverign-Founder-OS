use clap::{Parser, Subcommand};
use sovereign_audit_ledger::{hash_bytes, AppendInput, AuditLedger};
use sovereign_capability::{CapabilityIssuer, IssueOptions};
use sovereign_contracts::{ActionRequest, AutomationLevel, DataClass};
use sovereign_identity::DeviceIdentity;
use sovereign_policy::PolicyEngine;
use sovereign_sandbox::{ExecutionRequest, SandboxExecutor};
use sovereign_vault::Vault;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sovereign", about = "Sovereign Agent Runtime CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize local device identity, vault, and ledger
    Init,
    /// Run the secure kernel demo workflow
    Demo,
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
        Commands::Status => cmd_status()?,
    }
    Ok(())
}

fn cmd_init() -> Result<(), Box<dyn std::error::Error>> {
    let root = data_dir();
    std::fs::create_dir_all(&root)?;

    let device_path = root.join("device.json");
    if !device_path.exists() {
        let device = DeviceIdentity::generate();
        device.save(&device_path)?;
        println!("device identity: {}", device.device_id);
    } else {
        let device = DeviceIdentity::load(&device_path)?;
        println!("device identity: {} (existing)", device.device_id);
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
        let ledger = AuditLedger::load(&ledger_path, &device.public_key_b64)?;
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

    let mut sandbox = SandboxExecutor::new(vec!["email.draft".into()], issuer.public_key_b64());
    let result = sandbox.execute(ExecutionRequest {
        token: &token,
        venture_id: "ven_demo",
        actor_id: "agent_builder",
        tool: "email",
        operation: "draft",
        resource: "customer:acme",
        input: serde_json::json!({"subject": "Proposal for Acme Ltd."}),
    })?;
    println!("\n== Sandbox execution ==");
    println!("{}", serde_json::to_string_pretty(&result.output)?);

    let decision_hash = hash_bytes(&serde_json::to_vec(&decision)?);
    let ledger_path = root.join("ledger.json");
    let mut ledger = if ledger_path.exists() {
        AuditLedger::load(&ledger_path, &device.public_key_b64)?
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
