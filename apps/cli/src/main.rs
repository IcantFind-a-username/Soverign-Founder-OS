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
    /// Run the local app (Workspace + Security Center) on 127.0.0.1
    Ui {
        /// Port to bind on loopback
        #[arg(long, default_value_t = 7787)]
        port: u16,
        /// Do not open the browser automatically
        #[arg(long)]
        no_open: bool,
    },
    /// Demonstrate model-gateway health-aware failover and the Red-data guard
    ModelCheck,
    /// Demonstrate durable workflow checkpoints resuming across a crash
    WorkflowDemo,
    /// Verify an exported bundle offline: format, identity binding, signed chain
    VerifyExport {
        /// Path to a JSON bundle produced by the app's "Export all my data"
        path: PathBuf,
    },
    /// Self-audit: reconcile local state against the signed audit chain
    Integrity,
    /// Internal: compile one artifact from stdin in a killable worker process.
    /// Not for direct use — spawned by the runtime to isolate untrusted
    /// Wasmtime compilation. Reads digest(32)||module bytes, writes the
    /// serialized module to stdout.
    #[command(name = "__compile-worker", hide = true)]
    CompileWorker,
}

/// The hidden subcommand name the runtime spawns for out-of-process
/// compilation; kept in one place so the parent and the CLI agree.
pub const COMPILE_WORKER_SUBCOMMAND: &str = "__compile-worker";

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
        Commands::Ui { port, no_open } => ui::run(port, data_dir(), !no_open)?,
        Commands::ModelCheck => cmd_model_check(),
        Commands::WorkflowDemo => cmd_workflow_demo()?,
        Commands::VerifyExport { path } => cmd_verify_export(&path)?,
        Commands::Integrity => cmd_integrity()?,
        Commands::CompileWorker => {
            let code =
                sovereign_sandbox::run_compile_worker(std::io::stdin().lock(), std::io::stdout());
            std::process::exit(i32::from(code));
        }
    }
    Ok(())
}

fn cmd_integrity() -> Result<(), Box<dyn std::error::Error>> {
    let store = workspace::Store::open(&data_dir())?;
    let report = store.integrity_check()?;

    let check = |ok: bool| if ok { "PASS" } else { "FAIL" };
    println!("Self-audit — state reconciled against the signed audit chain");
    println!(
        "  signed audit chain {}  ({} events)",
        check(report.chain_verified),
        report.events
    );
    let critical = report
        .findings
        .iter()
        .filter(|finding| finding.severity == "critical")
        .count();
    let warnings = report.findings.len() - critical;
    if report.findings.is_empty() {
        println!("  state vs. evidence  PASS");
    } else {
        println!(
            "  state vs. evidence  {}  ({critical} critical, {warnings} warnings)",
            if critical == 0 { "PASS" } else { "FAIL" }
        );
        for finding in &report.findings {
            println!(
                "    [{}] {} — {}",
                finding.severity, finding.resource, finding.detail
            );
        }
    }
    if report.ok {
        println!("\nVERIFIED — every state on disk is backed by signed evidence.");
        Ok(())
    } else {
        // Fail closed with a non-zero exit so scripts can trust the verdict.
        Err("integrity check FAILED — see findings above".into())
    }
}

fn cmd_verify_export(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let bundle: serde_json::Value = serde_json::from_slice(&bytes)?;
    let report = workspace::verify_export(&bundle)?;

    let check = |ok: bool| if ok { "PASS" } else { "FAIL" };
    println!("Verifying {}", path.display());
    println!("  format tag         {}", check(report.format_ok));
    println!("  device id          {}", report.device_id);
    println!("  identity binding   {}", check(report.identity_bound));
    println!(
        "  signed audit chain {}  ({} events)",
        check(report.audit_chain_verified),
        report.audit_events
    );
    println!(
        "  state             {} customers · {} documents · {} signed approvals",
        report.customers, report.documents, report.signed_approvals
    );
    for note in &report.notes {
        println!("  note: {note}");
    }
    if report.ok {
        println!("\nVERIFIED — this bundle is intact and bound to the device that signed it.");
        Ok(())
    } else {
        // Fail closed with a non-zero exit so scripts can trust the verdict.
        Err("verification FAILED — see notes above".into())
    }
}

fn cmd_workflow_demo() -> Result<(), Box<dyn std::error::Error>> {
    use sovereign_workflow::{StepContext, WorkflowRunner, WorkflowStep};

    struct NamedStep {
        name: &'static str,
        crash: bool,
    }
    impl WorkflowStep for NamedStep {
        fn name(&self) -> &str {
            self.name
        }
        fn run(&self, context: &StepContext<'_>) -> Result<Vec<u8>, String> {
            if self.crash {
                println!("    · step `{}` interrupted (simulated crash)", self.name);
                return Err("process killed mid-step".into());
            }
            println!("    · executing step `{}`", self.name);
            Ok(format!("{}:{}", context.workflow_id, self.name).into_bytes())
        }
    }
    fn step(name: &'static str, crash: bool) -> Box<dyn WorkflowStep> {
        Box::new(NamedStep { name, crash })
    }

    let dir = data_dir().join("workflow-demo");
    let _ = std::fs::remove_dir_all(&dir);
    let names = [
        "generate_offer",
        "create_invoice",
        "build_plan",
        "security_checklist",
    ];

    println!("Durable workflow · crash-safe checkpoints + idempotent resume\n");
    println!("== First process: crashes during step 3 ==");
    let mut first: Vec<Box<dyn WorkflowStep>> = names.iter().map(|n| step(n, false)).collect();
    first[2] = step(names[2], true);
    let crashed = WorkflowRunner::open(&dir, "founder-onboarding")?.run(&first);
    println!(
        "  first run ended with: {}",
        match &crashed {
            Ok(_) => "completed".to_string(),
            Err(error) => error.to_string(),
        }
    );

    println!("\n== Second process (another node): resumes the full workflow ==");
    let full: Vec<Box<dyn WorkflowStep>> = names.iter().map(|n| step(n, false)).collect();
    let summary = WorkflowRunner::open(&dir, "founder-onboarding")?.run(&full)?;
    println!(
        "\n  steps executed on resume: {:?} (steps 0,1 replayed from receipts, not re-run)",
        summary.executed_now
    );
    println!("  total receipts: {}", summary.receipts.len());
    let _ = std::fs::remove_dir_all(&dir);
    println!("\nKill the process mid-workflow. Another node resumes from the last valid step.");
    Ok(())
}

fn cmd_model_check() {
    use sovereign_model::{
        DeterministicProvider, Health, ModelGateway, ModelRequest, ProviderTrust,
    };

    println!("Model gateway · health-aware failover + Red-data guard");
    println!("(providers are deterministic local stand-ins, not LLMs)\n");

    // Primary local model is down; a cloud backup is healthy; a local
    // fallback is healthy. Removing/downing the primary must not stop work.
    let gateway = ModelGateway::new(vec![
        Box::new(DeterministicProvider::local("local-primary", Health::Down)),
        Box::new(DeterministicProvider::cloud(
            "cloud-backup",
            Health::Healthy,
        )),
        Box::new(DeterministicProvider::local(
            "local-fallback",
            Health::Healthy,
        )),
    ]);
    println!("providers: {:?}", gateway.provider_ids());

    let amber = ModelRequest {
        task: "draft_outreach".into(),
        prompt: "Draft a short note to Dr. Tan.".into(),
        data_class: DataClass::Amber,
        max_output_chars: 4096,
    };
    match gateway.complete(&amber) {
        Ok((response, disclosure)) => {
            println!("\n== Amber request ==");
            println!(
                "  primary down -> served by {} ({:?})",
                response.provider_id, response.provider_trust
            );
            println!("  failover path: {:?}", disclosure.skipped);
        }
        Err(error) => println!("  unexpected: {error}"),
    }

    let red = ModelRequest {
        task: "classify_customer_pii".into(),
        prompt: "<red-zone customer record>".into(),
        data_class: DataClass::Red,
        max_output_chars: 4096,
    };
    match gateway.complete(&red) {
        Ok((response, disclosure)) => {
            println!("\n== Red request ==");
            println!(
                "  cloud backup skipped for confidentiality; served locally by {} ({:?})",
                response.provider_id, response.provider_trust
            );
            let leaked = disclosure.provider_trust != ProviderTrust::Local;
            println!("  red data left the device: {leaked}");
        }
        Err(error) => println!("  Red request denied (no local provider): {error}"),
    }

    println!("\nModels are replaceable. Red data stays local. Output is a draft, never authority.");
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
