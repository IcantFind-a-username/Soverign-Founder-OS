mod demo;
mod ui;
mod workspace;

use clap::{Parser, Subcommand};
use sovereign_audit_ledger::AuditLedger;
use sovereign_capability::{CapabilityIssuer, IssueOptions};
use sovereign_contracts::{ActionRequest, AutomationLevel, DataClass};
use sovereign_identity::DeviceIdentity;
use sovereign_policy::PolicyEngine;
use sovereign_sandbox::{SandboxExecutor, WasmExecutionRequest};
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
    /// Run the story-driven secure kernel demo (real signatures, real denials)
    Demo {
        /// Run straight through without pausing between acts
        #[arg(long)]
        fast: bool,
    },
    /// Run a mechanical check of the import-free Phase A Wasmtime path
    SandboxCheck,
    /// Show vault entry names
    Status,
    /// Serve the local Security Center dashboard on 127.0.0.1
    Ui {
        /// Port to bind on loopback
        #[arg(long, default_value_t = 7787)]
        port: u16,
    },
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
        Commands::Demo { fast } => demo::run(fast, data_dir())?,
        Commands::SandboxCheck => cmd_sandbox_check()?,
        Commands::Status => cmd_status()?,
        Commands::Ui { port } => ui::run(port, data_dir())?,
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
