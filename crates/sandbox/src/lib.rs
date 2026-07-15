use chrono::Utc;
use sovereign_capability::{CapabilityError, CapabilityValidator, ValidationContext};
use sovereign_contracts::CapabilityToken;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("capability error: {0}")]
    Capability(#[from] CapabilityError),
    #[error("tool not allowed: {0}")]
    ToolNotAllowed(String),
    #[error("execution failed: {0}")]
    ExecutionFailed(String),
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

#[derive(Debug)]
pub struct ExecutionResult {
    pub output: serde_json::Value,
    pub sandboxed: bool,
}

/// Isolated tool executor. Only runs after capability validation.
#[derive(Debug)]
pub struct SandboxExecutor {
    validator: CapabilityValidator,
    allowed_tools: Vec<String>,
}

impl SandboxExecutor {
    pub fn new(
        allowed_tools: Vec<String>,
        trusted_issuer_public_key_b64: impl Into<String>,
    ) -> Self {
        Self {
            validator: CapabilityValidator::new(trusted_issuer_public_key_b64),
            allowed_tools,
        }
    }

    pub fn execute(
        &mut self,
        request: ExecutionRequest<'_>,
    ) -> Result<ExecutionResult, SandboxError> {
        let tool_key = format!("{}.{}", request.tool, request.operation);
        if !self
            .allowed_tools
            .iter()
            .any(|t| t == &tool_key || t == request.tool)
        {
            return Err(SandboxError::ToolNotAllowed(tool_key));
        }

        self.validator.validate(
            request.token,
            ValidationContext {
                venture_id: request.venture_id,
                actor_id: request.actor_id,
                tool: request.tool,
                operation: request.operation,
                resource: request.resource,
                now: Utc::now(),
            },
        )?;

        // MVP: simulate tool execution in-process. Real impl uses WASM/container.
        let output = serde_json::json!({
            "status": "ok",
            "tool": request.tool,
            "operation": request.operation,
            "resource": request.resource,
            "echo": request.input,
            "sandboxed": true,
        });

        Ok(ExecutionResult {
            output,
            sandboxed: true,
        })
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
        let mut sandbox = SandboxExecutor::new(vec!["email.draft".into()], issuer.public_key_b64());
        let result = sandbox
            .execute(ExecutionRequest {
                token: &token,
                venture_id: "ven_1",
                actor_id: "agent",
                tool: "email",
                operation: "draft",
                resource: "customer:1",
                input: serde_json::json!({"subject": "Hello"}),
            })
            .unwrap();
        assert!(result.sandboxed);
    }

    #[test]
    fn rejects_disallowed_tool() {
        let (issuer, token) = sample_token();
        let mut sandbox = SandboxExecutor::new(vec!["file.read".into()], issuer.public_key_b64());
        let err = sandbox
            .execute(ExecutionRequest {
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
