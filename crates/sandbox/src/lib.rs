mod wasm;

use chrono::Utc;
use sovereign_capability::{CapabilityError, CapabilityValidator, ValidationContext};
use sovereign_contracts::CapabilityToken;
use thiserror::Error;

pub use wasm::{WasmExecutionResult, WasmSandbox, WasmSandboxLimits, DEFAULT_ENTRYPOINT};

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("capability error: {0}")]
    Capability(#[from] CapabilityError),
    #[error("tool not allowed: {0}")]
    ToolNotAllowed(String),
    #[error("execution failed: {0}")]
    ExecutionFailed(String),
    #[error("invalid sandbox runtime limits")]
    InvalidRuntimeLimits,
    #[error("sandbox runtime initialization failed: {0}")]
    RuntimeInitialization(String),
    #[error("sandbox runtime is busy")]
    RuntimeBusy,
    #[error("sandbox runtime unavailable: {0}")]
    RuntimeUnavailable(String),
    #[error("WebAssembly module is {actual} bytes; maximum is {maximum}")]
    ModuleTooLarge { actual: usize, maximum: usize },
    #[error("invalid WebAssembly module: {0}")]
    InvalidModule(String),
    #[error("host import denied: {module}::{name}")]
    ForbiddenImport { module: String, name: String },
    #[error("required WebAssembly entrypoint not found: {0}")]
    MissingEntrypoint(String),
    #[error("incompatible WebAssembly entrypoint `{entrypoint}`: expected () -> i32: {detail}")]
    InvalidEntrypoint { entrypoint: String, detail: String },
    #[error("WebAssembly instantiation failed: {0}")]
    InstantiationFailed(String),
    #[error("WebAssembly fuel exhausted")]
    FuelExhausted,
    #[error("WebAssembly wall-clock deadline exceeded")]
    DeadlineExceeded,
    #[error("WebAssembly resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),
    #[error("WebAssembly guest trapped: {0}")]
    GuestTrap(String),
}

pub struct ExecutionRequest<'a> {
    pub token: &'a CapabilityToken,
    pub venture_id: &'a str,
    pub actor_id: &'a str,
    pub tool: &'a str,
    pub operation: &'a str,
    pub resource: &'a str,
    pub input: serde_json::Value,
}

pub struct WasmExecutionRequest<'a> {
    pub token: &'a CapabilityToken,
    pub venture_id: &'a str,
    pub actor_id: &'a str,
    pub tool: &'a str,
    pub operation: &'a str,
    pub resource: &'a str,
    pub module: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionRuntime {
    InProcessSimulation,
    WasmtimeCorePhaseA,
}

impl ExecutionRuntime {
    /// Reports only whether guest instructions ran behind a Wasm memory and
    /// control-flow boundary. It does not imply artifact trust, durable audit,
    /// effect authorization, or production readiness.
    pub fn is_isolated(self) -> bool {
        matches!(self, Self::WasmtimeCorePhaseA)
    }

    pub fn is_production_ready(self) -> bool {
        false
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::InProcessSimulation => "in_process_simulation",
            Self::WasmtimeCorePhaseA => "wasmtime_core_phase_a",
        }
    }
}

#[derive(Debug)]
pub struct ExecutionResult {
    pub output: serde_json::Value,
    pub runtime: ExecutionRuntime,
}

/// Capability-gated executor with explicit simulated and isolated paths.
#[derive(Debug)]
pub struct SandboxExecutor {
    validator: CapabilityValidator,
    allowed_tools: Vec<String>,
    wasm: WasmSandbox,
}

impl SandboxExecutor {
    pub fn new(
        allowed_tools: Vec<String>,
        trusted_issuer_public_key_b64: impl Into<String>,
    ) -> Result<Self, SandboxError> {
        Self::with_wasm_limits(
            allowed_tools,
            trusted_issuer_public_key_b64,
            WasmSandboxLimits::default(),
        )
    }

    pub fn with_wasm_limits(
        allowed_tools: Vec<String>,
        trusted_issuer_public_key_b64: impl Into<String>,
        wasm_limits: WasmSandboxLimits,
    ) -> Result<Self, SandboxError> {
        Ok(Self {
            validator: CapabilityValidator::new(trusted_issuer_public_key_b64),
            allowed_tools,
            wasm: WasmSandbox::new(wasm_limits)?,
        })
    }

    /// Legacy Stage 1 demo path. It is deliberately labelled as non-isolated.
    pub fn execute_simulated(
        &mut self,
        request: ExecutionRequest<'_>,
    ) -> Result<ExecutionResult, SandboxError> {
        self.authorize(
            request.token,
            request.venture_id,
            request.actor_id,
            request.tool,
            request.operation,
            request.resource,
        )?;

        let output = serde_json::json!({
            "status": "simulated",
            "tool": request.tool,
            "operation": request.operation,
            "resource": request.resource,
            "echo": request.input,
            "runtime": ExecutionRuntime::InProcessSimulation.as_str(),
            "isolated": false,
            "external_effect_performed": false,
        });

        Ok(ExecutionResult {
            output,
            runtime: ExecutionRuntime::InProcessSimulation,
        })
    }

    /// Execute an import-free module inside a fresh Phase A Wasmtime instance.
    ///
    /// This path has no host effects. Capability V1 does not bind the artifact
    /// or exact input, so it must not be used to authorize effectful tools.
    pub fn execute_wasm(
        &mut self,
        request: WasmExecutionRequest<'_>,
    ) -> Result<WasmExecutionResult, SandboxError> {
        self.authorize(
            request.token,
            request.venture_id,
            request.actor_id,
            request.tool,
            request.operation,
            request.resource,
        )?;
        self.wasm.execute(request.module)
    }

    fn authorize(
        &mut self,
        token: &CapabilityToken,
        venture_id: &str,
        actor_id: &str,
        tool: &str,
        operation: &str,
        resource: &str,
    ) -> Result<(), SandboxError> {
        let tool_key = format!("{tool}.{operation}");
        if !self
            .allowed_tools
            .iter()
            .any(|allowed| allowed == &tool_key || allowed == tool)
        {
            return Err(SandboxError::ToolNotAllowed(tool_key));
        }

        self.validator.validate(
            token,
            ValidationContext {
                venture_id,
                actor_id,
                tool,
                operation,
                resource,
                now: Utc::now(),
            },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sovereign_capability::{CapabilityIssuer, IssueOptions};
    use sovereign_contracts::{ActionRequest, AutomationLevel, DataClass};
    use sovereign_policy::PolicyEngine;

    fn sample_token() -> (CapabilityIssuer, CapabilityToken) {
        let engine = PolicyEngine::new();
        let decision = engine.evaluate(ActionRequest {
            actor_id: "agent".into(),
            venture_id: "ven_1".into(),
            tool: "email".into(),
            operation: "draft".into(),
            resource: "customer:1".into(),
            data_class: DataClass::Amber,
            automation_level: AutomationLevel::L1Draft,
        });
        let issuer = CapabilityIssuer::new();
        let token = issuer
            .issue(&decision, IssueOptions::default(), false)
            .unwrap();
        (issuer, token)
    }

    #[test]
    fn executes_with_valid_token() {
        let (issuer, token) = sample_token();
        let mut sandbox =
            SandboxExecutor::new(vec!["email.draft".into()], issuer.public_key_b64()).unwrap();
        let result = sandbox
            .execute_simulated(ExecutionRequest {
                token: &token,
                venture_id: "ven_1",
                actor_id: "agent",
                tool: "email",
                operation: "draft",
                resource: "customer:1",
                input: serde_json::json!({"subject": "Hello"}),
            })
            .unwrap();
        assert_eq!(result.runtime, ExecutionRuntime::InProcessSimulation);
        assert!(!result.runtime.is_isolated());
        assert_eq!(result.output["status"], "simulated");
        assert_eq!(result.output["external_effect_performed"], false);
    }

    #[test]
    fn rejects_disallowed_tool() {
        let (issuer, token) = sample_token();
        let mut sandbox =
            SandboxExecutor::new(vec!["file.read".into()], issuer.public_key_b64()).unwrap();
        let err = sandbox
            .execute_simulated(ExecutionRequest {
                token: &token,
                venture_id: "ven_1",
                actor_id: "agent",
                tool: "email",
                operation: "draft",
                resource: "customer:1",
                input: serde_json::json!({}),
            })
            .unwrap_err();
        assert!(matches!(err, SandboxError::ToolNotAllowed(_)));
    }
}
