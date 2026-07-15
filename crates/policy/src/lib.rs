use chrono::Utc;
use sovereign_contracts::{ActionRequest, AutomationLevel, DataClass, PolicyDecision};
use uuid::Uuid;

/// High-risk tools that always require human approval before execution.
const HIGH_RISK_TOOLS: &[&str] = &[
    "email.send",
    "payment.transfer",
    "contract.sign",
    "deploy.production",
    "file.delete",
    "social.publish",
];

/// Operations blocked for cloud-bound data classes.
const CLOUD_BLOCKED_CLASSES: &[DataClass] = &[DataClass::Red];

/// Deterministic policy engine. LLM output never bypasses this layer.
#[derive(Debug, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(&self, request: ActionRequest) -> PolicyDecision {
        let mut denial_reasons = Vec::new();
        let mut approval_reasons = Vec::new();

        if CLOUD_BLOCKED_CLASSES.contains(&request.data_class) && request.tool.starts_with("cloud.")
        {
            denial_reasons.push("red-zone data cannot be sent to cloud tools");
        }

        if request.automation_level >= AutomationLevel::L2ApproveExecute {
            approval_reasons.push("L2+ actions require human approval");
        }

        let tool_key = format!("{}.{}", request.tool, request.operation);
        if HIGH_RISK_TOOLS
            .iter()
            .any(|t| tool_key == *t || request.tool == *t)
        {
            approval_reasons.push("high-risk tool requires explicit approval");
        }

        if request.resource.contains("..") || request.resource.starts_with('/') {
            denial_reasons.push("path traversal or absolute path access denied");
        }

        let allowed = denial_reasons.is_empty();
        let requires_approval = !approval_reasons.is_empty();
        let reason = denial_reasons
            .into_iter()
            .chain(approval_reasons)
            .collect::<Vec<_>>();
        let reason = if reason.is_empty() {
            "allowed by default policy".to_string()
        } else {
            reason.join("; ")
        };

        PolicyDecision {
            decision_id: Uuid::new_v4(),
            allowed,
            reason,
            requires_approval,
            evaluated_at: Utc::now(),
            request,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(tool: &str, op: &str, class: DataClass, level: AutomationLevel) -> ActionRequest {
        ActionRequest {
            actor_id: "agent_1".into(),
            venture_id: "ven_1".into(),
            tool: tool.into(),
            operation: op.into(),
            resource: "customer:123".into(),
            data_class: class,
            automation_level: level,
        }
    }

    #[test]
    fn blocks_red_data_to_cloud() {
        let engine = PolicyEngine::new();
        let decision = engine.evaluate(req(
            "cloud.model",
            "infer",
            DataClass::Red,
            AutomationLevel::L1Draft,
        ));
        assert!(!decision.allowed);
    }

    #[test]
    fn high_risk_requires_approval() {
        let engine = PolicyEngine::new();
        let decision = engine.evaluate(req(
            "email",
            "send",
            DataClass::Green,
            AutomationLevel::L2ApproveExecute,
        ));
        assert!(decision.requires_approval);
    }

    #[test]
    fn blocks_path_traversal() {
        let engine = PolicyEngine::new();
        let mut request = req("file", "read", DataClass::Green, AutomationLevel::L1Draft);
        request.resource = "../secrets".into();
        let decision = engine.evaluate(request);
        assert!(!decision.allowed);
    }
}
