mod compile_worker;
mod wasm;

use std::collections::BTreeSet;

use chrono::Utc;
use sovereign_artifact::{AdmittedArtifact, Digest, OperationSelector, PreparedInvocation};
use sovereign_capability::approval::SignedApprovalV1;
use sovereign_capability::v2::{
    CapabilityTokenV2, CapabilityV2Error, CapabilityV2ValidationContext, CapabilityValidatorV2,
    TrustedClock as CapabilityV2Clock,
};
use sovereign_capability::{CapabilityError, CapabilityValidator, ValidationContext};
use sovereign_contracts::CapabilityToken;
use sovereign_execution::{ExecutionIntent, ExecutionJournal, ExecutionOutcome, JournalError};
use sovereign_policy::PolicyAuthorizationV2;
use thiserror::Error;
use uuid::Uuid;

pub use compile_worker::{run_compile_worker, CompileWorker};
pub use wasm::{WasmExecutionResult, WasmSandbox, WasmSandboxLimits, DEFAULT_ENTRYPOINT};

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("capability error: {0}")]
    Capability(#[from] CapabilityError),
    #[error("Capability V2 authorization failed: {0}")]
    CapabilityV2(#[from] CapabilityV2Error),
    #[error("tool not allowed: {0}")]
    ToolNotAllowed(String),
    #[error("the presented admitted-artifact handle does not match this invocation's artifact")]
    ArtifactNotAdmitted,
    #[error("the compilation worker failed: {0}")]
    CompileWorkerFailed(String),
    #[error("the compilation worker exceeded its wall-clock deadline and was killed")]
    CompileWorkerTimeout,
    #[error("verified operation is not present in the exact structured allowlist")]
    VerifiedOperationNotAllowed { selector: OperationSelector },
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
    #[error("execution intent could not be persisted; execution denied")]
    ExecutionIntentNotPersisted,
    #[error("execution journal unavailable: {0}")]
    ExecutionJournalUnavailable(String),
}

impl SandboxError {
    /// Stable failure code for journal terminal records. Raw engine strings
    /// are diagnostic detail, not part of this stable taxonomy.
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::FuelExhausted => "fuel_exhausted",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::ResourceLimitExceeded(_) => "resource_limit",
            Self::GuestTrap(_) => "guest_trap",
            Self::MissingEntrypoint(_) => "missing_abi",
            Self::InvalidEntrypoint { .. } => "incompatible_abi",
            Self::InvalidModule(_) => "invalid_module",
            Self::InstantiationFailed(_) => "instantiate_failed",
            Self::ForbiddenImport { .. } => "forbidden_import",
            Self::ModuleTooLarge { .. } => "module_too_large",
            _ => "execution_failed",
        }
    }
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
    WasmtimeVerifiedPureComputeV2,
}

impl ExecutionRuntime {
    /// Reports only whether guest instructions ran behind a Wasm memory and
    /// control-flow boundary. It does not imply artifact trust, durable audit,
    /// effect authorization, or production readiness.
    pub fn is_isolated(self) -> bool {
        matches!(
            self,
            Self::WasmtimeCorePhaseA | Self::WasmtimeVerifiedPureComputeV2
        )
    }

    pub fn is_production_ready(self) -> bool {
        false
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::InProcessSimulation => "in_process_simulation",
            Self::WasmtimeCorePhaseA => "wasmtime_core_phase_a",
            Self::WasmtimeVerifiedPureComputeV2 => "wasmtime_verified_pure_compute_v2",
        }
    }
}

#[derive(Debug)]
pub struct ExecutionResult {
    pub output: serde_json::Value,
    pub runtime: ExecutionRuntime,
}

/// Exact V2 execution request. The executable and canonical input bindings
/// come only from `invocation`; this type deliberately has no module bytes,
/// module path, entrypoint, raw input, tool string, or resource override.
///
/// V1 tokens are a different type and cannot enter this request:
///
/// ```compile_fail
/// use sovereign_capability::v2::CapabilityTokenV2;
/// use sovereign_contracts::CapabilityToken;
///
/// fn v1_is_not_v2(token: &CapabilityToken) -> &CapabilityTokenV2 {
///     token
/// }
/// ```
///
/// Raw executable bytes cannot be attached to this request:
///
/// ```compile_fail
/// use sovereign_sandbox::VerifiedExecutionRequest;
///
/// fn smuggle_module(request: &mut VerifiedExecutionRequest<'_>, bytes: &[u8]) {
///     request.module = bytes;
/// }
/// ```
pub struct VerifiedExecutionRequest<'a> {
    pub token: &'a CapabilityTokenV2,
    pub invocation: &'a PreparedInvocation,
    /// Proof of local admission (RFC 0002 step 8): only an owner-admitted
    /// artifact may enter the execution path. The executor fail-closed binds
    /// this handle to the invocation's artifact by component and manifest
    /// digest before consuming anything.
    pub admitted: &'a AdmittedArtifact,
    pub venture_id: &'a str,
    pub subject_id: &'a str,
    pub session_id: Uuid,
    pub policy_decision: &'a PolicyAuthorizationV2,
}

/// Capability V2 executor for publisher-verified, import-free pure-compute artifacts.
///
/// The allowlist is an exact set of structured selectors. There are no dotted
/// string aliases, prefixes, or wildcards. Authorization is consumed before
/// Wasmtime sees the artifact, so a guest compile, instantiation, or runtime
/// failure still spends the one-use capability.
///
/// The current core Wasm ABI is `() -> i32`. Canonical input is authenticated
/// by the capability, but this foundation does not claim to deliver that input
/// into guest memory. It also exposes no host functions or external effects,
/// and never falls back to the V1 or simulated executors.
#[derive(Debug)]
pub struct VerifiedSandboxExecutor<C: CapabilityV2Clock> {
    validator: CapabilityValidatorV2<C>,
    allowed_operations: BTreeSet<OperationSelector>,
    wasm: WasmSandbox,
    journal: Option<ExecutionJournal>,
}

impl<C: CapabilityV2Clock> VerifiedSandboxExecutor<C> {
    pub fn new(
        allowed_operations: Vec<OperationSelector>,
        validator: CapabilityValidatorV2<C>,
    ) -> Result<Self, SandboxError> {
        Self::with_wasm_limits(allowed_operations, validator, WasmSandboxLimits::default())
    }

    pub fn with_wasm_limits(
        allowed_operations: Vec<OperationSelector>,
        validator: CapabilityValidatorV2<C>,
        wasm_limits: WasmSandboxLimits,
    ) -> Result<Self, SandboxError> {
        Ok(Self {
            validator,
            allowed_operations: allowed_operations.into_iter().collect(),
            wasm: WasmSandbox::new(wasm_limits)?,
            journal: None,
        })
    }

    /// Attach a crash-safe execution journal. Intent is then durably recorded
    /// before the capability is consumed (RFC 0002 ordering), and a terminal
    /// verdict is recorded after execution. If intent cannot be persisted,
    /// execution is denied. Without a journal, behavior is unchanged.
    pub fn with_execution_journal(mut self, journal: ExecutionJournal) -> Self {
        self.journal = Some(journal);
        self
    }

    /// Route untrusted module compilation through a killable, resource-limited
    /// worker process (RFC 0002 compilation threat surface). Without it,
    /// compilation runs in-process (Phase A).
    pub fn with_compile_worker(mut self, worker: CompileWorker) -> Self {
        self.wasm = self.wasm.with_compile_worker(worker);
        self
    }

    pub fn execute(
        &mut self,
        request: VerifiedExecutionRequest<'_>,
    ) -> Result<WasmExecutionResult, SandboxError> {
        self.execute_approved(request, None)
    }

    /// Execute with RFC 0003 signed approval evidence for approval-required
    /// decisions. `execute` delegates here with no evidence; tokens carrying
    /// an approval claim fail closed unless the matching signed approval is
    /// presented and the validator was configured with approval trust.
    pub fn execute_approved(
        &mut self,
        request: VerifiedExecutionRequest<'_>,
        approval: Option<&SignedApprovalV1>,
    ) -> Result<WasmExecutionResult, SandboxError> {
        // Local admission is required before anything else is even attempted
        // (RFC 0002 step 8: only the admitted handle may enter the execution
        // path). Fail closed *before* the journal opens or the one-use
        // capability is consumed, so presenting an unadmitted artifact burns
        // nothing. Digest equality over the owned bytes binds the handle to
        // exactly this invocation's artifact.
        let admitted = request.admitted.artifact();
        let invoked = request.invocation.artifact();
        if admitted.component_digest() != invoked.component_digest()
            || admitted.manifest_digest() != invoked.manifest_digest()
        {
            return Err(SandboxError::ArtifactNotAdmitted);
        }

        let selector = request.invocation.operation();
        if !self.allowed_operations.contains(selector) {
            return Err(SandboxError::VerifiedOperationNotAllowed {
                selector: selector.clone(),
            });
        }

        // RFC 0002 ordering: durable intent BEFORE consuming the capability,
        // so that a crash cannot execute without leaving a recoverable trace.
        let guard = match &self.journal {
            Some(journal) => Some(
                journal
                    .begin(ExecutionIntent {
                        execution_id: Uuid::new_v4(),
                        component_digest_hex: request
                            .invocation
                            .artifact()
                            .component_digest()
                            .as_hex(),
                        canonical_input_digest_hex: request.invocation.input_digest().as_hex(),
                        requested_at_unix: Utc::now().timestamp(),
                    })
                    .map_err(map_journal_error)?,
            ),
            None => None,
        };

        let authorized = self.validator.authorize_and_consume_approved(
            request.token,
            CapabilityV2ValidationContext {
                venture_id: request.venture_id,
                subject_id: request.subject_id,
                session_id: request.session_id,
                policy_decision: request.policy_decision,
                prepared_invocation: request.invocation,
            },
            approval,
        );
        if let Err(error) = authorized {
            // Authorization denied: nothing executed. Record a terminal
            // Failed so recovery never sees this as indeterminate.
            if let Some(guard) = guard {
                let _ = guard.finish(ExecutionOutcome::Failed {
                    code: "authorization_denied".into(),
                });
            }
            return Err(error.into());
        }

        if let Some(guard) = &guard {
            guard.started().map_err(map_journal_error)?;
        }

        let result = self.wasm.execute_verified(request.invocation);
        if let Some(guard) = guard {
            let outcome = match &result {
                Ok(execution) => ExecutionOutcome::Completed {
                    result_hash_hex: result_hash(execution),
                },
                Err(error) => ExecutionOutcome::Failed {
                    code: error.stable_code().into(),
                },
            };
            guard.finish(outcome).map_err(map_journal_error)?;
        }
        result
    }
}

fn result_hash(result: &WasmExecutionResult) -> String {
    let descriptor = serde_json::json!({
        "exit_code": result.exit_code,
        "fuel_consumed": result.fuel_consumed,
    });
    Digest::of_bytes(&serde_json::to_vec(&descriptor).unwrap_or_default()).as_hex()
}

fn map_journal_error(error: JournalError) -> SandboxError {
    match error {
        JournalError::IntentNotPersisted => SandboxError::ExecutionIntentNotPersisted,
        other => SandboxError::ExecutionJournalUnavailable(other.to_string()),
    }
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
