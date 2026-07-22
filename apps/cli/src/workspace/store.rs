use super::util::storage;
use super::*;
use std::path::Path;

use sovereign_audit_ledger::{hash_bytes, AppendInput, AuditLedger};
use sovereign_contracts::{ActionRequest, AutomationLevel, DataClass};
use sovereign_identity::DeviceIdentity;
use sovereign_policy::PolicyEngine;
use sovereign_vault::Vault;

impl Store {
    pub fn open(root: &Path) -> Result<Self, WorkspaceError> {
        std::fs::create_dir_all(root).map_err(storage)?;
        let device_path = root.join("device.json");
        let device = if device_path.exists() {
            DeviceIdentity::load(&device_path).map_err(storage)?
        } else {
            let device = DeviceIdentity::generate();
            device.save(&device_path).map_err(storage)?;
            device
        };
        Ok(Self {
            root: root.to_path_buf(),
            device,
            policy: PolicyEngine::new(),
        })
    }

    pub fn load(&self) -> Result<Workspace, WorkspaceError> {
        let vault = Vault::init(self.root.join("vault")).map_err(storage)?;
        match vault.get(WORKSPACE_VAULT_ENTRY) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| WorkspaceError::Storage(format!("corrupt workspace: {error}"))),
            Err(sovereign_vault::VaultError::NotFound(_)) => Ok(Workspace {
                version: WORKSPACE_VERSION,
                ..Workspace::default()
            }),
            Err(error) => Err(storage(error)),
        }
    }

    pub(super) fn save(&self, workspace: &Workspace) -> Result<(), WorkspaceError> {
        let mut vault = Vault::init(self.root.join("vault")).map_err(storage)?;
        let bytes = serde_json::to_vec(workspace).map_err(storage)?;
        vault.put(WORKSPACE_VAULT_ENTRY, &bytes).map_err(storage)?;
        Ok(())
    }

    /// Evaluate policy for a workflow action; deny fails closed, and both
    /// allowed and denied evaluations can be audited by the caller.
    pub(super) fn check_policy(
        &self,
        tool: &str,
        operation: &str,
        resource: &str,
        data_class: DataClass,
        automation_level: AutomationLevel,
    ) -> (bool, bool, String) {
        let decision = self.policy.evaluate(ActionRequest {
            actor_id: "founder".into(),
            venture_id: "workspace".into(),
            tool: tool.into(),
            operation: operation.into(),
            resource: resource.into(),
            data_class,
            automation_level,
        });
        (
            decision.allowed,
            decision.requires_approval,
            decision.reason,
        )
    }

    pub(super) fn record(
        &self,
        action: &str,
        resource: &str,
        payload: serde_json::Value,
    ) -> Result<(), WorkspaceError> {
        let ledger_path = self.root.join("ledger.json");
        let mut ledger = if ledger_path.exists() {
            AuditLedger::load(&ledger_path, self.device.public_key_b64()).map_err(storage)?
        } else {
            AuditLedger::new()
        };
        let payload_digest = hash_bytes(&serde_json::to_vec(&payload).map_err(storage)?);
        ledger
            .append(
                AppendInput {
                    venture_id: "workspace".into(),
                    actor_id: "founder".into(),
                    action: action.into(),
                    resource: resource.into(),
                    capability_id: None,
                    payload: serde_json::json!({
                        "summary": payload,
                        "payload_digest": payload_digest,
                    }),
                    policy_decision_hash: None,
                },
                &self.device,
            )
            .map_err(storage)?;
        ledger.save(&ledger_path).map_err(storage)?;
        Ok(())
    }
}
