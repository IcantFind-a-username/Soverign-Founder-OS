# Roadmap

## Development Philosophy

**Sovereign Founder OS is the product. Build its minimum Trust Layer first, prove it through one real founder workflow, and expand from there.**

Implementation starts with the Sovereign Runtime secure kernel because real business automation needs enforceable authority and recovery. This sequencing does not redefine the complete product as developer infrastructure.

Wrong path: simultaneously building global legal, global tax, blockchain wallet, auto-marketing, multi-agent chat, desktop, mobile, and enterprise cloud.

Right path:

```text
Sovereign Runtime secure kernel
  → Demonstrable adversarial tests
  → One real enterprise workflow
  → Distributed recovery
  → Jurisdiction capabilities
  → Plugin ecosystem
```

## Stages and Exit Criteria

### Stage 0: Project Constitution — Complete

**Deliverables:**
- [x] Product vision and positioning consolidated in README.md
- [x] ARCHITECTURE.md
- [x] THREAT_MODEL.md
- [x] Privacy target design (`docs/design/privacy-model.md`)
- [x] ROADMAP.md
- [x] LICENSE (Apache 2.0)
- [ ] RFC: canonical task contract
- [ ] RFC: policy decision contract

**Exit criteria:** Any contributor can explain what the system protects, who it trusts, and who it does not trust.

---

### Stage 1: Secure Kernel — In Progress

**Deliverables:**
- [x] Local encrypted Vault (`crates/vault`)
- [x] Device identity and signing (`crates/identity`)
- [x] Deterministic Policy Engine (`crates/policy`)
- [x] Capability Token issuer/validator (`crates/capability`)
- [x] Sandboxed tool executor — capability-gated prototype (`crates/sandbox`)
- [x] Append-only signed audit ledger (`crates/audit-ledger`)
- [ ] WASM/container isolation for sandbox
  - [x] Phase A: import-free Wasmtime mechanics with guest execution ceilings (non-production)
  - [ ] Phase B: verified artifact and invocation boundary
    - [x] Role-separated COSE/JCS publisher manifest verification
    - [x] Immutable artifact snapshot, strict schema/resource binding, and `PreparedInvocation`
    - [x] Exact-bound Capability V2 and verified pure-compute Core Wasm path (process-local)
    - [x] Locally signed admission record and content-addressed artifact store
    - [x] Signed human approval evidence bound into Capability V2 (RFC 0003, process-local one-use)
    - [ ] Verified executor requires a locally admitted artifact handle
    - [ ] Killable compilation worker and trusted compiled cache
    - [ ] Component/WIT input ABI
  - [ ] Phase C: durable authorization and crash-safe evidence
    - [x] Durable Authority Store: atomic cross-process one-use consumption of tokens, approvals, and idempotency keys
    - [x] Crash-safe execution journal: durable intent before consume, terminal result after, Indeterminate recovery
    - [ ] Crash-safe signed-audit intent/result ordering (ledger migration) and execution receipts
  - [ ] Phase D: reviewed WIT host interfaces and high-risk backend
    - [x] First host effect: audited, path-safe local outbox file-write broker (no network)
    - [ ] Reviewed WIT Component host interface and per-host-call authorization
- [ ] Adversarial integration tests
  - [x] Phase A: malicious Wasm import, loop, memory, table, ABI, and state tests
  - [x] Phase B foundation: manifest/artifact/input substitution, strict fields, trust state, V1/V2 separation, same-process replay, and backend downgrade tests
  - [x] Admission store: on-disk substitution, record forgery/cross-role, revoked-key, poisoned-entry, orphan-temp, and symlink tests
  - [ ] Full Stage 1 authorization, replay, audit, and backend downgrade suite

**Exit criteria:** A malicious agent cannot read files or execute external actions without authorization.

---

### Stage 2: Model Resilience — Minimal foundation

**Deliverables:**
- [x] Unified model interface (`crates/model`: `ModelProvider` trait, `ModelGateway`)
- [x] Ordered multi-provider routing with local/cloud trust
- [x] Health detection (Healthy/Degraded/Down) and automatic failover
- [x] Data-disclosure records and a Red-data-stays-local guard
- [ ] Real provider adapters behind an egress broker (deterministic stand-ins today)

**Exit criteria:** Removing the primary model configuration does not stop core workflows. *(Demonstrated: `sovereign model-check`; providers are deterministic local stand-ins, not LLMs.)*

---

### Stage 3: Workflow Recovery — Minimal foundation

**Deliverables:**
- [x] Durable workflow checkpoints (`crates/workflow`, crash-safe atomic rewrite)
- [x] Deterministic per-step idempotency keys (UUID v5)
- [x] Step replay: completed steps are never re-executed on resume
- [ ] Encrypted backup targets
- [ ] Multi-machine node promotion and failover (replication, leases)

**Exit criteria:** Killing the primary process allows another node to recover from the last valid step. *(Demonstrated: `sovereign workflow-demo`; "another node" is another runner over the same durable directory.)*

---

### Stage 4: Founder OS Demo

**Deliverables:**
- Sovereign Enterprise Graph
- Customer onboarding workflow (consulting / software services)
- Offer generation
- Contract draft (marked as draft)
- Invoice draft
- Founder Dashboard (6 core UI pages)

**First workflow:**

```text
Describe service
  → Generate Offer
  → Create prospect
  → Prepare interview questions
  → Generate contract draft
  → Create project workspace
  → Create invoice draft
  → Build delivery plan
  → Generate security checklist
  → Update Sovereign Enterprise Graph
```

**Exit criteria:** A new user completes a real business flow without reading source code.

---

### Stage 5: Security Gauntlet

**Deliverables:**
- Adversarial test suite
- Chaos CLI (`sovereign chaos kill-model`, etc.)
- Framework comparison report
- Public security benchmark: **Agent Security Gauntlet**

**Exit criteria:** Security advantages demonstrated through reproducible experiments, not marketing.

**Kill Everything demo:**

```text
1.  Create one-person consulting company
2.  AI generates client proposal and contract draft
3.  Kill primary model → auto-switch to backup
4.  Revoke backup account → local model degradation
5.  Stop primary node → recovery node takes over
6.  Install malicious plugin → Policy Engine blocks key access
7.  Prompt injection attempts data exfiltration → blocked
8.  Restore primary node → event log verified, work continues
9.  Export all company data and recovery package
```

> Target result: Kill the model, the server and the plugin. The company keeps running.

---

### Stage 6: Jurisdiction Pack

**Deliverables:**
- Jurisdiction schema and versioning
- Source and date tracking
- Deterministic rule engine for tax
- Professional review process
- First pack: **Singapore** (digital services / consulting / Micro-SaaS)

**Exit criteria:** Every legal or tax conclusion traceable to rule, source, and assumption.

---

### Stage 7: Ecosystem

**Deliverables:**
- Plugin SDK (WASM/WASI)
- Signed plugin registry
- Pack registry
- OpenClaw Skill compatibility layer
- MCP compatibility
- Community governance

**Exit criteria:** Third parties publish secure extensions without modifying the core repository.

---

## Sovereign Runtime Alpha — First Public Release

Minimum requirements before public Alpha:

1. Local encrypted Vault
2. Device identity and signing
3. Unified Model Gateway
4. Two cloud models + one local model
5. Automatic model failover
6. Deterministic Policy Engine
7. Capability Token
8. Sandboxed tool execution
9. Signed event log
10. Encrypted backup
11. Workflow checkpointing
12. Failover demonstration
13. Prompt injection test suite
14. Malicious plugin blocking demonstration
15. One complete enterprise workflow

## Explicit Non-Goals (Early Stages)

- Global legal coverage
- Global tax filing
- Automatic payments or contract signing
- Custom cryptographic algorithms
- Custom blockchain implementation
- Personal data on public chains
- Unrestricted auto-email or browser control
- In-process third-party plugins
- Dependency on official cloud to run
- LLM as final permission authority
- All OS and mobile platforms simultaneously
- Dozens of low-quality agents

## Success Metrics

### Product
- New user completes end-to-end enterprise workflow
- User understands every approval request
- User can fully export data
- Core business manageable offline

### Security
- 100% tool calls have Capability Token
- 100% high-risk actions have approval record
- 100% cloud model calls have Data Disclosure Record
- Malicious plugin cannot access undeclared resources
- Audit log tampering is detectable

### Resilience
- Any single model vendor failure does not block data access
- Any single non-critical replica failure does not cause data loss
- Primary node failure → workflow recoverable
- Recovery works without official servers
- Backup restore continuously auto-tested

### Community
- External contributors submit security tests
- Third-party projects adopt Runtime
- Threat model cited in security research
- Community-contributed Jurisdiction Packs

## Star Milestones (Validation, Not Promises)

| Stars | Meaning |
| --- | --- |
| 100 | Positioning and demo understood by strangers |
| 1,000 | Runtime useful to real projects |
| 10,000 | Plugin SDK, benchmarks, community forming |
| 100,000 | De facto standard for agent security or sovereign AI |

## First GUI Pages (Stage 4)

1. Onboarding (5-step wizard)
2. Founder Command Center
3. Work Detail
4. Approval Center
5. Security Center
6. Settings / Models / Backup

See [docs/product/gui-design.zh-CN.md](docs/product/gui-design.zh-CN.md) for the current UI design draft.
