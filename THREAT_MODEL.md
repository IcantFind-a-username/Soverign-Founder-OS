# Threat Model v0.1

## Scope

This document describes threats against Sovereign Founder OS and Sovereign Runtime during the Alpha phase. It is a living document and will be updated as the implementation matures.

Mitigations are labelled **Current** when enforced by the repository today and **Alpha target** when they are required before the relevant Alpha capability may ship. A target control is not a claim of current protection.

## Assets to Protect

| Asset | Sensitivity |
| --- | --- |
| User root keys and company keys | Critical |
| Customer PII and contact lists | Critical |
| Contracts, invoices, financial records | Critical |
| API secrets and credentials | Critical |
| Audit event ledger | Critical |
| Enterprise graph state | High |
| Agent plans and deliverables | High |
| Model API keys (provider accounts) | High |
| Plugin manifests and signatures | Medium |
| Public market research data | Low |

## Trust Boundaries

### Trusted (with verification)

- **Current:** deterministic Policy Engine
- **Current:** role-separated signing primitives, publisher/Authority trust stores, and Capability V1/V2 validators
- **Current:** cryptographic vault prototype (Rust core)
- **Current:** signed append-only audit ledger prototype
- **Current foundation:** RFC 0003 signed human approval evidence — approval-required Capability V2 tokens are issued only with owner-signed, exactly bound, one-use (process-local) evidence, and still fail closed without it. Durable cross-process approval consumption remains an Alpha target.

### Untrusted (always)

- All LLM outputs and suggestions
- External web pages, emails, PDFs, documents
- MCP server responses
- Third-party plugins
- Python agent workers
- Cloud model providers (for confidentiality, not availability)

### Semi-trusted (constrained)

- **Alpha target:** cloud model providers (availability and inference only; data minimized via classification)
- **Alpha target:** secondary storage replicas (encrypted, server-blind)
- **Alpha target:** recovery nodes (encrypted copies only)

## Threat Categories

### T1: Prompt Injection

**Description:** Malicious instructions embedded in external content attempt to override system policy, exfiltrate data, or trigger unauthorized tool use.

**Mitigations:**
- **Alpha target:** Untrusted Content Zone — external content is data, never instructions
- **Alpha target:** Planner/Executor separation
- **Current:** Policy Engine makes implemented authorization decisions deterministically
- **Current foundation:** Capability V2 scopes one publisher-verified pure-compute invocation exactly
- **Current foundation / Alpha target:** adversarial fixtures exist; the full Alpha gauntlet remains incomplete

### T2: Tool Privilege Escalation

**Description:** An agent or plugin attempts to expand its permissions beyond what was granted.

**Mitigations:**
- **Current foundation:** short-lived, one-use Capability V2 binds the exact artifact, operation, input commitments, and resource commitments; replay state is process-local
- **Current:** Authority and Publisher signing roles are distinct, and an AI agent cannot make its own key trusted
- **Current foundation:** strict publisher manifest enforcement and import-free Core Wasm isolation
- **Alpha target:** durable token revocation, container/micro-VM backends, and reviewed effectful host interfaces
- **Alpha target:** 100% of real tool effects require a valid capability and durable evidence

### T3: Credential Exfiltration

**Description:** An agent, plugin, or compromised model path attempts to read and transmit secrets.

**Mitigations:**
- **Alpha target:** Red-zone data never leaves the device through any model or tool path
- **Alpha target:** agents never hold root keys
- **Current:** both Wasmtime paths expose no filesystem, network, environment, WASI, or other host imports; the only host effect is an owner-controlled local outbox file write, performed by the trusted host after full authorization, refusing Red data and path escape
- **Alpha target:** Data Disclosure Record for every cloud model call
- **Alpha target:** output scanning for sensitive patterns

### T4: Model Provider Failure or Revocation

**Description:** Primary AI provider becomes unavailable, changes terms, or revokes API access.

**Mitigations:**
- **Alpha target:** multi-vendor Model Mesh with automatic failover
- **Alpha target:** local model degradation path
- **Design invariant / Alpha target:** no business-critical state stored only at a provider
- **Alpha target:** workflows recoverable from local checkpoints

### T5: Single Point of Failure

**Description:** Failure of one device, cloud, database, or key destroys business continuity.

**Mitigations:**
- **Alpha target:** public Single Point of Failure Registry with documented countermeasures
- **Alpha target:** encrypted multi-device replication (Levels 1–4)
- **Alpha target:** event-sourced state with signed checkpoints
- **Alpha target:** export and offline recovery without official servers

### T6: Audit Log Tampering

**Description:** An attacker or compromised agent attempts to alter or delete operation history.

**Mitigations:**
- **Current:** append-only signed event-ledger prototype with a hash chain
- **Current primitive / migration pending:** a role-separated Audit COSE signer exists; the ledger still uses its legacy device-signature encoding
- **Alpha target:** periodic Merkle-root anchoring
- **Alpha target:** an Auditor role that cannot execute external actions
- **Alpha target:** tamper detection during recovery validation

### T7: Split-Brain in Distributed Mode

**Description:** Two nodes simultaneously issue conflicting authoritative writes (contracts, payments, permissions).

**Mitigations:**
- **Alpha target:** leader lease with fencing tokens
- **Alpha target:** authoritative vs. eventually-consistent data separation
- **Current foundation:** V2 idempotency and replay checks within one process only
- **Alpha target:** durable cross-process idempotency, version checks, and multi-node approval for high-value operations

### T8: Supply Chain Attack (Plugins/Dependencies)

**Description:** Malicious or compromised plugin, dependency, or MCP server.

**Mitigations:**
- **Current foundation:** role-separated publisher manifest signature verification and exact artifact digest binding
- **Current:** dependency audit and dependency-review CI checks
- **Alpha target:** SBOM and SLSA-aligned build provenance
- **Current foundation / Alpha target:** adversarial plugin fixtures exist; the full completion gate remains incomplete
- **Current:** pure-compute plugins receive no network, filesystem, environment, WASI, or other host imports

### T9: Memory Poisoning

**Description:** Adversarial content corrupts long-term agent memory or enterprise state.

**Mitigations:**
- **Alpha target:** memory writes validated by an independent checker
- **Alpha target:** authoritative state changes only through signed events
- **Alpha target:** source attribution on all business artifacts

## Automation Levels (Risk Control)

| Level | Capability | Examples |
| --- | --- | --- |
| L0 Suggest | Recommendations only | Strategy advice |
| L1 Draft | Generate but not execute | Email drafts, contract drafts |
| L2 Approve-then-execute | User confirms before action | Send email, deploy code |
| L3 Bounded automation | Auto within budget/scope limits | Scheduled backups, health checks |

Financial, legal, and irreversible operations: **maximum L2**.

## Out of Scope (Alpha)

- Nation-state adversaries with physical device access
- Custom cryptographic algorithm attacks (we use audited libraries only)
- Full HSM and confidential computing (planned for later stages)
- Global legal correctness guarantees

## Verification Requirements

Alpha release must pass:

- [x] Current deterministic-policy fixture rejects prompt attempts to self-authorize high-risk actions
- [x] Current import-free Wasm fixtures cannot access filesystem, network, environment, WASI, or undeclared host interfaces
- [x] Current policy fixture rejects Red data sent through a cloud-labelled tool
- [x] Capability V2 rejects same-process replay and idempotency conflicts
- [ ] Capability revocation and replay remain rejected across restart and concurrent processes
- [ ] Full prompt-injection and data-disclosure paths pass the Alpha gauntlet
- [ ] Primary model failure does not block data access
- [x] Current audit-ledger fixture detects hash-chain/signature modification
- [ ] Recovery works without official cloud servers

Chaos CLI commands for reproducible testing — see [ROADMAP.md](ROADMAP.md) Stage 5.

## Reporting

Security vulnerabilities: see [SECURITY.md](SECURITY.md) for responsible disclosure process.
