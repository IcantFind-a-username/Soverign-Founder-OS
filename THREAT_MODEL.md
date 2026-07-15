# Threat Model v0.1

## Scope

This document describes threats against Sovereign Founder OS and Sovereign Runtime during the Alpha phase. It is a living document and will be updated as the implementation matures.

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

- Deterministic Policy Engine
- Capability Token issuer and validator
- Cryptographic vault (Rust core)
- Signed audit ledger
- Human owner approval for high-risk actions

### Untrusted (always)

- All LLM outputs and suggestions
- External web pages, emails, PDFs, documents
- MCP server responses
- Third-party plugins
- Python agent workers
- Cloud model providers (for confidentiality, not availability)

### Semi-trusted (constrained)

- Cloud model providers (availability and inference only; data minimized via classification)
- Secondary storage replicas (encrypted, server-blind)
- Recovery nodes (encrypted copies only)

## Threat Categories

### T1: Prompt Injection

**Description:** Malicious instructions embedded in external content attempt to override system policy, exfiltrate data, or trigger unauthorized tool use.

**Mitigations:**
- Untrusted Content Zone — external content is data, never instructions
- Planner/Executor separation
- Policy Engine makes all execution decisions deterministically
- Capability tokens scope every tool call
- Adversarial test suite (required for Alpha release)

### T2: Tool Privilege Escalation

**Description:** An agent or plugin attempts to expand its permissions beyond what was granted.

**Mitigations:**
- Short-lived capability tokens bound to specific resources
- Tokens cannot be self-issued by agents
- Plugin manifest enforcement
- WASM/container isolation
- 100% tool calls require valid capability token (success metric)

### T3: Credential Exfiltration

**Description:** An agent, plugin, or compromised model path attempts to read and transmit secrets.

**Mitigations:**
- Red-zone data never leaves device
- Agents never hold root keys
- Sandbox default: no network, read-only filesystem
- Data Disclosure Record for every cloud model call
- Output scanning for sensitive patterns

### T4: Model Provider Failure or Revocation

**Description:** Primary AI provider becomes unavailable, changes terms, or revokes API access.

**Mitigations:**
- Multi-vendor Model Mesh with automatic failover
- Local model degradation path
- No business-critical state stored at provider
- Workflows recoverable from local checkpoints

### T5: Single Point of Failure

**Description:** Failure of one device, cloud, database, or key destroys business continuity.

**Mitigations:**
- Public Single Point of Failure Registry with documented countermeasures
- Encrypted multi-device replication (Levels 1–4)
- Event-sourced state with signed checkpoints
- Export and offline recovery without official servers

### T6: Audit Log Tampering

**Description:** An attacker or compromised agent attempts to alter or delete operation history.

**Mitigations:**
- Append-only signed event ledger
- Hash chain linking events
- Periodic Merkle root anchoring (future)
- Auditor role cannot execute external actions
- Tamper detection in recovery validation

### T7: Split-Brain in Distributed Mode

**Description:** Two nodes simultaneously issue conflicting authoritative writes (contracts, payments, permissions).

**Mitigations:**
- Leader lease with fencing tokens
- Authoritative vs. eventually-consistent data separation
- Idempotency keys and version checks
- Multi-node approval for high-value operations

### T8: Supply Chain Attack (Plugins/Dependencies)

**Description:** Malicious or compromised plugin, dependency, or MCP server.

**Mitigations:**
- Plugin manifest with signature verification
- Supply chain scanning (SBOM, dependency audit)
- SLSA-aligned build provenance
- Adversarial plugin fixtures in CI
- Plugin default-deny network and filesystem

### T9: Memory Poisoning

**Description:** Adversarial content corrupts long-term agent memory or enterprise state.

**Mitigations:**
- Memory writes validated by independent checker
- State changes only through signed events
- Source attribution on all artifacts

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

- [ ] Prompt injection cannot change system permissions
- [ ] Malicious plugin cannot read undeclared resources
- [ ] Red data cannot enter cloud model requests
- [ ] Token replay is rejected
- [ ] Primary model failure does not block data access
- [ ] Audit log modification is detectable
- [ ] Recovery works without official cloud servers

Chaos CLI commands for reproducible testing — see [ROADMAP.md](ROADMAP.md) Stage 5.

## Reporting

Security vulnerabilities: see [SECURITY.md](SECURITY.md) for responsible disclosure process.
