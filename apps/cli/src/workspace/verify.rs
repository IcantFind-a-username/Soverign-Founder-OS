use super::*;

use sovereign_audit_ledger::AuditLedger;
use sovereign_contracts::AuditEvent;
use sovereign_identity::device_id_from_public_key_b64;

/// Verify an exported bundle independently and offline. Pure over its input:
/// it opens no store, loads no keys, and touches no network, so it can check a
/// backup on any machine. When `ok` is true the bundle is well-formed, its
/// audit history is bound to the `device_id` it declares, and the entire signed
/// hash chain re-verifies. Any failure is reported in `notes`, never hidden.
pub fn verify_export(bundle: &serde_json::Value) -> Result<ExportVerification, WorkspaceError> {
    let mut notes = Vec::new();

    let format = bundle
        .get("format")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let format_ok = format == EXPORT_FORMAT;
    if !format_ok {
        notes.push(format!("unexpected format tag: {format:?}"));
    }
    let version = bundle
        .get("version")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let device_id = bundle
        .get("device_id")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_owned();

    let events: Vec<AuditEvent> = match bundle.get("audit_events") {
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|error| WorkspaceError::Invalid(format!("audit_events malformed: {error}")))?,
        None => Vec::new(),
    };
    let audit_events = events.len();

    // Identity binding and full-chain verification, from the events alone. Each
    // event embeds the signing public key, so the chain — hash linkage and
    // Ed25519 signatures — is checkable without any external key material.
    let (identity_bound, audit_chain_verified) = if events.is_empty() {
        (false, true)
    } else {
        let signing_key = events[0].device_public_key_b64.clone();
        let uniform_key = events
            .iter()
            .all(|event| event.device_public_key_b64 == signing_key);
        if !uniform_key {
            notes.push("audit events are signed by more than one key".into());
        }
        let identity_bound = match device_id_from_public_key_b64(&signing_key) {
            Ok(expected) if expected == device_id => true,
            Ok(_) => {
                notes.push("device_id does not match the audit-signing key".into());
                false
            }
            Err(error) => {
                notes.push(format!("audit-signing key is invalid: {error}"));
                false
            }
        };
        let chain_ok = match AuditLedger::from_events(events, signing_key) {
            Ok(_) => true,
            Err(error) => {
                notes.push(format!("audit chain failed verification: {error}"));
                false
            }
        };
        (identity_bound && uniform_key, chain_ok)
    };

    let workspace = bundle.get("workspace");
    let array_len = |key: &str| {
        workspace
            .and_then(|value| value.get(key))
            .and_then(|value| value.as_array())
            .map(|array| array.len())
            .unwrap_or(0)
    };
    let customers = array_len("customers");
    let documents = array_len("documents");
    let signed_approvals = workspace
        .and_then(|value| value.get("approvals"))
        .and_then(|value| value.as_array())
        .map(|approvals| {
            approvals
                .iter()
                .filter(|approval| {
                    approval
                        .get("evidence")
                        .map(|evidence| !evidence.is_null())
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0);

    let ok = if audit_events == 0 {
        notes.push("no audit history in this bundle — nothing to cryptographically verify".into());
        format_ok
    } else {
        format_ok && identity_bound && audit_chain_verified
    };

    Ok(ExportVerification {
        format_ok,
        version,
        device_id,
        identity_bound,
        audit_events,
        audit_chain_verified,
        customers,
        documents,
        signed_approvals,
        ok,
        notes,
    })
}
