use std::time::Duration;

use sovereign_capability::{CapabilityError, CapabilityIssuer, IssueOptions};
use sovereign_contracts::{ActionRequest, AutomationLevel, DataClass};
use sovereign_policy::PolicyEngine;
use sovereign_sandbox::{
    ExecutionRuntime, SandboxError, SandboxExecutor, WasmExecutionRequest, WasmSandbox,
    WasmSandboxLimits,
};

fn compile(wat_source: &str) -> Vec<u8> {
    wat::parse_str(wat_source).unwrap()
}

fn module_returning(value: i32) -> Vec<u8> {
    compile(&format!(
        r#"(module
            (func (export "sovereign_run") (result i32)
                i32.const {value}))"#
    ))
}

fn infinite_loop_module() -> Vec<u8> {
    compile(
        r#"(module
            (func (export "sovereign_run") (result i32)
                (loop $forever
                    i32.const 1
                    drop
                    br $forever)
                unreachable))"#,
    )
}

#[test]
fn executes_in_a_real_wasmtime_runtime() {
    let sandbox = WasmSandbox::new(WasmSandboxLimits::default()).unwrap();
    let result = sandbox.execute(&module_returning(7)).unwrap();

    assert_eq!(result.exit_code, 7);
    assert_eq!(result.runtime, ExecutionRuntime::WasmtimeCorePhaseA);
    assert!(result.runtime.is_isolated());
    assert!(!result.runtime.is_production_ready());
    assert!(result.fuel_consumed > 0);
}

#[test]
fn rejects_all_host_imports_by_default() {
    let sandbox = WasmSandbox::new(WasmSandboxLimits::default()).unwrap();
    for (module_name, import_name) in [
        ("wasi_snapshot_preview1", "environ_get"),
        ("wasi_snapshot_preview1", "path_open"),
        ("wasi_snapshot_preview1", "sock_accept"),
        ("host", "read_secret"),
    ] {
        let module = compile(&format!(
            r#"(module
                (import "{module_name}" "{import_name}" (func $forbidden))
                (func (export "sovereign_run") (result i32)
                    i32.const 0))"#
        ));
        let error = sandbox.execute(&module).unwrap_err();
        assert!(matches!(
            error,
            SandboxError::ForbiddenImport { module, name }
                if module == module_name && name == import_name
        ));
    }
}

#[test]
fn fuel_stops_infinite_guest_code() {
    let limits = WasmSandboxLimits {
        fuel: 100,
        wall_timeout: Duration::from_secs(2),
        ..WasmSandboxLimits::default()
    };
    let sandbox = WasmSandbox::new(limits).unwrap();

    assert!(matches!(
        sandbox.execute(&infinite_loop_module()),
        Err(SandboxError::FuelExhausted)
    ));
}

#[test]
fn wall_deadline_stops_infinite_guest_code() {
    let limits = WasmSandboxLimits {
        fuel: u64::MAX,
        wall_timeout: Duration::from_millis(20),
        epoch_tick: Duration::from_millis(2),
        ..WasmSandboxLimits::default()
    };
    let sandbox = WasmSandbox::new(limits).unwrap();

    assert!(matches!(
        sandbox.execute(&infinite_loop_module()),
        Err(SandboxError::DeadlineExceeded)
    ));
}

#[test]
fn start_function_limits_and_traps_keep_their_failure_class() {
    let start_loop = compile(
        r#"(module
            (func $start
                (loop $forever
                    br $forever))
            (start $start)
            (func (export "sovereign_run") (result i32)
                i32.const 0))"#,
    );
    let fuel_limited = WasmSandbox::new(WasmSandboxLimits {
        fuel: 100,
        wall_timeout: Duration::from_secs(2),
        ..WasmSandboxLimits::default()
    })
    .unwrap();
    assert!(matches!(
        fuel_limited.execute(&start_loop),
        Err(SandboxError::FuelExhausted)
    ));

    let deadline_limited = WasmSandbox::new(WasmSandboxLimits {
        fuel: u64::MAX,
        wall_timeout: Duration::from_millis(20),
        epoch_tick: Duration::from_millis(2),
        ..WasmSandboxLimits::default()
    })
    .unwrap();
    assert!(matches!(
        deadline_limited.execute(&start_loop),
        Err(SandboxError::DeadlineExceeded)
    ));

    let start_trap = compile(
        r#"(module
            (func $start unreachable)
            (start $start)
            (func (export "sovereign_run") (result i32)
                i32.const 0))"#,
    );
    let sandbox = WasmSandbox::new(WasmSandboxLimits::default()).unwrap();
    assert!(matches!(
        sandbox.execute(&start_trap),
        Err(SandboxError::GuestTrap(_))
    ));
}

#[test]
fn recursive_guest_code_hits_the_wasm_stack_ceiling() {
    let sandbox = WasmSandbox::new(WasmSandboxLimits {
        max_wasm_stack_bytes: 64 * 1024,
        fuel: u64::MAX,
        wall_timeout: Duration::from_secs(2),
        ..WasmSandboxLimits::default()
    })
    .unwrap();
    let recursive = compile(
        r#"(module
            (func $recurse (result i32)
                call $recurse)
            (export "sovereign_run" (func $recurse)))"#,
    );

    assert!(matches!(
        sandbox.execute(&recursive),
        Err(SandboxError::GuestTrap(_))
    ));
}

#[test]
fn memory_growth_cannot_cross_the_host_limit() {
    let limits = WasmSandboxLimits {
        max_memory_bytes: 64 * 1024,
        ..WasmSandboxLimits::default()
    };
    let sandbox = WasmSandbox::new(limits).unwrap();
    let memory_bomb = compile(
        r#"(module
            (memory 1)
            (func (export "sovereign_run") (result i32)
                i32.const 1
                memory.grow
                drop
                i32.const 0))"#,
    );

    let result = sandbox.execute(&memory_bomb);
    assert!(
        matches!(result, Err(SandboxError::ResourceLimitExceeded(ref resource)) if resource == "linear memory"),
        "unexpected memory limit result: {result:?}"
    );
}

#[test]
fn initial_memory_cannot_cross_the_host_limit() {
    let sandbox = WasmSandbox::new(WasmSandboxLimits {
        max_memory_bytes: 64 * 1024,
        ..WasmSandboxLimits::default()
    })
    .unwrap();
    let oversized_initial_memory = compile(
        r#"(module
            (memory 2)
            (func (export "sovereign_run") (result i32)
                i32.const 0))"#,
    );

    assert!(matches!(
        sandbox.execute(&oversized_initial_memory),
        Err(SandboxError::ResourceLimitExceeded(resource)) if resource == "linear memory"
    ));
}

#[test]
fn table_growth_cannot_cross_the_host_limit() {
    let sandbox = WasmSandbox::new(WasmSandboxLimits {
        max_table_elements: 1,
        ..WasmSandboxLimits::default()
    })
    .unwrap();
    let table_bomb = compile(
        r#"(module
            (table 1 funcref)
            (func (export "sovereign_run") (result i32)
                ref.null func
                i32.const 1
                table.grow
                drop
                i32.const 0))"#,
    );

    assert!(matches!(
        sandbox.execute(&table_bomb),
        Err(SandboxError::ResourceLimitExceeded(resource)) if resource == "table elements"
    ));
}

#[test]
fn initial_table_cannot_cross_the_host_limit() {
    let sandbox = WasmSandbox::new(WasmSandboxLimits {
        max_table_elements: 1,
        ..WasmSandboxLimits::default()
    })
    .unwrap();
    let oversized_initial_table = compile(
        r#"(module
            (table 2 funcref)
            (func (export "sovereign_run") (result i32)
                i32.const 0))"#,
    );

    assert!(matches!(
        sandbox.execute(&oversized_initial_table),
        Err(SandboxError::ResourceLimitExceeded(resource)) if resource == "table elements"
    ));
}

#[test]
fn every_execution_gets_fresh_guest_state() {
    let sandbox = WasmSandbox::new(WasmSandboxLimits::default()).unwrap();
    let stateful_module = compile(
        r#"(module
            (global $counter (mut i32) (i32.const 0))
            (func (export "sovereign_run") (result i32)
                global.get $counter
                i32.const 1
                i32.add
                global.set $counter
                global.get $counter))"#,
    );

    assert_eq!(sandbox.execute(&stateful_module).unwrap().exit_code, 1);
    assert_eq!(sandbox.execute(&stateful_module).unwrap().exit_code, 1);
}

#[test]
fn invalid_oversized_and_wrong_abi_modules_fail_closed() {
    let sandbox = WasmSandbox::new(WasmSandboxLimits {
        max_module_bytes: 64,
        ..WasmSandboxLimits::default()
    })
    .unwrap();

    assert!(matches!(
        sandbox.execute(b"not wasm"),
        Err(SandboxError::InvalidModule(_))
    ));
    assert!(matches!(
        sandbox.execute(&[0_u8; 65]),
        Err(SandboxError::ModuleTooLarge { .. })
    ));

    let no_entrypoint = compile("(module (func (export \"other\") (result i32) i32.const 0))");
    assert!(matches!(
        sandbox.execute(&no_entrypoint),
        Err(SandboxError::MissingEntrypoint(_))
    ));

    let wrong_signature = compile(
        r#"(module
            (func (export "sovereign_run") (param i32) (result i32)
                local.get 0))"#,
    );
    assert!(matches!(
        sandbox.execute(&wrong_signature),
        Err(SandboxError::InvalidEntrypoint { .. })
    ));
}

#[test]
fn zero_runtime_limits_are_rejected() {
    for limits in [
        WasmSandboxLimits {
            max_memory_bytes: 0,
            ..WasmSandboxLimits::default()
        },
        WasmSandboxLimits {
            fuel: 0,
            ..WasmSandboxLimits::default()
        },
        WasmSandboxLimits {
            wall_timeout: Duration::ZERO,
            ..WasmSandboxLimits::default()
        },
        WasmSandboxLimits {
            wall_timeout: Duration::from_millis(1),
            epoch_tick: Duration::from_millis(2),
            ..WasmSandboxLimits::default()
        },
    ] {
        assert!(matches!(
            WasmSandbox::new(limits),
            Err(SandboxError::InvalidRuntimeLimits)
        ));
    }
}

#[test]
fn unsupported_wasm_proposals_fail_validation() {
    let sandbox = WasmSandbox::new(WasmSandboxLimits::default()).unwrap();
    let simd_module = compile(
        r#"(module
            (func (export "sovereign_run") (result i32)
                v128.const i32x4 0 0 0 0
                drop
                i32.const 0))"#,
    );

    assert!(matches!(
        sandbox.execute(&simd_module),
        Err(SandboxError::InvalidModule(_))
    ));
}

#[test]
fn capability_is_checked_before_wasm_execution() {
    let decision = PolicyEngine::new().evaluate(ActionRequest {
        actor_id: "agent_builder".into(),
        venture_id: "ven_alpha".into(),
        tool: "document".into(),
        operation: "transform".into(),
        resource: "draft:1".into(),
        data_class: DataClass::Green,
        automation_level: AutomationLevel::L1Draft,
    });
    let issuer = CapabilityIssuer::new();
    let token = issuer
        .issue(&decision, IssueOptions::default(), false)
        .unwrap();
    let mut executor =
        SandboxExecutor::new(vec!["document.transform".into()], issuer.public_key_b64()).unwrap();
    let module = module_returning(0);

    let result = executor
        .execute_wasm(WasmExecutionRequest {
            token: &token,
            venture_id: "ven_alpha",
            actor_id: "agent_builder",
            tool: "document",
            operation: "transform",
            resource: "draft:1",
            module: &module,
        })
        .unwrap();
    assert_eq!(result.runtime, ExecutionRuntime::WasmtimeCorePhaseA);

    let error = executor
        .execute_wasm(WasmExecutionRequest {
            token: &token,
            venture_id: "ven_alpha",
            actor_id: "agent_attacker",
            tool: "document",
            operation: "transform",
            resource: "draft:1",
            module: &module,
        })
        .unwrap_err();
    assert!(matches!(
        error,
        SandboxError::Capability(CapabilityError::ActorMismatch)
    ));
}

#[test]
fn failed_guest_attempt_still_consumes_the_capability_use() {
    let decision = PolicyEngine::new().evaluate(ActionRequest {
        actor_id: "agent_builder".into(),
        venture_id: "ven_alpha".into(),
        tool: "document".into(),
        operation: "transform".into(),
        resource: "draft:failure".into(),
        data_class: DataClass::Green,
        automation_level: AutomationLevel::L1Draft,
    });
    let issuer = CapabilityIssuer::new();
    let token = issuer
        .issue(&decision, IssueOptions::default(), false)
        .unwrap();
    let mut executor =
        SandboxExecutor::new(vec!["document.transform".into()], issuer.public_key_b64()).unwrap();

    let first = executor.execute_wasm(WasmExecutionRequest {
        token: &token,
        venture_id: "ven_alpha",
        actor_id: "agent_builder",
        tool: "document",
        operation: "transform",
        resource: "draft:failure",
        module: b"not wasm",
    });
    assert!(matches!(first, Err(SandboxError::InvalidModule(_))));

    let second = executor.execute_wasm(WasmExecutionRequest {
        token: &token,
        venture_id: "ven_alpha",
        actor_id: "agent_builder",
        tool: "document",
        operation: "transform",
        resource: "draft:failure",
        module: &module_returning(0),
    });
    assert!(matches!(
        second,
        Err(SandboxError::Capability(CapabilityError::Exhausted))
    ));
}
