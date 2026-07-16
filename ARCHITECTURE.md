# Architecture

## Overview

Sovereign Founder OS is the complete product. In the target architecture, its business modules will share an authoritative Sovereign Enterprise Graph, use the Crew Orchestrator to coordinate AI work, and rely on the Sovereign Trust Layer for controlled execution and continuity.

Target product hierarchy:

```text
Sovereign Founder OS
├── Venture Studio
├── AI Crew
│   └── Crew Orchestrator
├── Product & Delivery
├── Customers & Growth
├── Finance / Legal / Tax
├── Founder Command Center
└── Sovereign Trust Layer
    └── Sovereign Runtime
        ├── Model Mesh
        ├── Policy Engine
        ├── Secure Vault
        ├── Audit Ledger
        ├── Tool Sandbox
        └── Recovery Mesh
```

The current implementation focuses on the Sovereign Runtime secure kernel. That is an implementation sequence, not a separate product identity: every runtime capability exists to support real Founder OS workflows.

## Current Stage 1 Architecture

The executable workspace currently consists of the Rust CLI, eight Runtime crates, and a cross-crate adversarial test package:

```text
sovereign-cli
├── contracts
├── identity
├── artifact
│   └── publisher COSE manifest → VerifiedArtifact → PreparedInvocation
├── policy
├── capability
│   ├── Capability V1 (legacy Phase A compatibility)
│   └── exact-bound, one-use Capability V2 (process-local state)
├── vault
├── audit-ledger
└── sandbox
    ├── import-free Wasmtime path (Phase A)
    └── verified pure-compute V2 path (Phase B foundation)

sovereign-adversarial-tests
```

Stage 1 currently provides prototypes for role-separated signing and trust stores, deterministic policy decisions, scoped and expiring capability tokens, encrypted local storage, a signed append-only audit ledger, and capability-gated sandbox execution. The Phase B foundation verifies a publisher-signed manifest, snapshots the exact artifact bytes, validates strict input and resource grants, prepares canonical invocation commitments, and binds them into Capability V2 before the verified executor starts. Both Wasmtime paths permit pure computation only, apply fuel, epoch, memory, table, and instance limits, and expose no host imports or WASI.

`VerifiedArtifact` proves publisher provenance and byte identity; it is not the target locally signed `AdmittedArtifact`. The current sandbox is not a production plugin boundary: there is no local admission record or content-addressed artifact store, compilation remains in-process, replay accounting is process-local, the core-Wasm ABI does not receive canonical input, the mechanical `sandbox-check` uses an ephemeral issuer, and no guest can invoke an audited external side effect. The Founder Command Center, Sovereign Enterprise Graph, Crew Orchestrator, Model Mesh, Domain Packs, Recovery Mesh, durable authorization, and production host interfaces are not implemented yet. See [ROADMAP.md](ROADMAP.md) and [RFC 0002](rfcs/0002-wasm-sandbox-and-plugin-capabilities.md).

The remaining sections describe the target architecture unless they explicitly state a current Stage 1 capability.

## Target Runtime and Trust Flow (Planned)

```text
Founder Command Center + Product Modules
              │
              ▼
       Mission Compiler
  (natural language → structured enterprise tasks)
              │
              ▼
   Sovereign Enterprise Graph
  (company, customers, contracts, assets, tax, security)
              │
              ▼
       Crew Orchestrator
 (assembles roles; plans never execute)
              │
              ▼
┌──────────────────────────────────┐
│      Sovereign Trust Layer       │
│  classification / permissions /  │
│  risk / approval / jurisdiction  │
└──────────────────────────────────┘
              │
              ▼
     Capability Token Issuer
  (short-lived, scoped, revocable tokens)
              │
              ▼
┌─────────────┬─────────────┬─────────────┐
│ Model Mesh  │ Tool Sandbox│ Domain Packs│
│ multi-vendor│ isolated    │ legal, tax, │
│ routing     │ execution   │ business    │
└─────────────┴─────────────┴─────────────┘
              │
              ▼
       Verification Layer
  (rules, second-model review, schema validation)
              │
              ▼
      Signed Event Ledger
              │
              ▼
 Encrypted Replication & Recovery Mesh
```

## Target Six-Plane Architecture (Planned)

| Plane | Responsibility |
| --- | --- |
| **Intelligence** | Models, agents, planning, reasoning |
| **Policy** | Deterministic permissions, risk, approval |
| **Execution** | Tools, browser, files, code execution |
| **Data** | Encrypted enterprise state, local storage |
| **Trust** | Identity, keys, signatures, audit, software provenance |
| **Recovery** | Replication, checkpoints, failover, disaster recovery |

## Sovereign Enterprise Graph (Planned)

The authoritative state of a company. Key entities:

```text
Founder, Legal Entity, Jurisdiction, Customer, Supplier,
Product, Service, Contract, Invoice, Payment, Asset,
Intellectual Property, Tax Obligation, Compliance Obligation,
Security Asset, Credential, Incident, Business Assumption,
Experiment, Metric, Decision, Approval, Artifact
```

Every agent operation must:

1. Read authorized enterprise state
2. Produce a structured plan
3. Request execution permissions
4. Produce verifiable deliverables
5. Update enterprise state
6. Leave a non-repudiable operation record

## Mutually Constrained Autonomy

| Role | Can Do | Cannot Do |
| --- | --- | --- |
| **Planner** | Create plans | Hold real tool credentials |
| **Policy Guard** | Allow/deny actions | Generate business goals |
| **Executor** | Execute approved actions | Expand its own permissions |
| **Auditor** | Verify and record | Execute external actions |
| **Recovery Controller** | Restore system | Modify normal business records |
| **Human Owner** | Final approval | Be bypassed for high-risk ops |

## Target Agent Execution Flow (Planned)

```text
Untrusted external content
        │
        ▼
Untrusted Content Zone
  (data only, never system instructions)
        │
        ▼
AI Planner / Analyst
  (proposes plan and actions)
        │
        ▼
Deterministic Policy Engine
  (validates permissions, scope, risk, approval)
        │
        ▼
Capability Token Issuer
  (short-lived, resource-bound token)
        │
        ▼
Sandboxed Executor
  (minimum privilege, temporary credentials)
        │
        ▼
Auditor + Signed Event Ledger
```

**Critical invariant:** "What the model suggests" and "What the system allows" are always separated.

## Crew Orchestrator (Planned)

The Crew Orchestrator turns a business goal into a temporary, constrained AI team. Agents are not permanently assigned roles. Crews are assembled per task based on:

- Current venture stage
- Task type
- Required tools
- Data sensitivity
- Cost budget
- Error risk
- Human approval requirements

Typical ephemeral roles: Researcher, Strategist, Builder, Critic, Operator, Evaluator.

When the task completes, the crew dissolves. Only results, evidence, and decision records persist.

## Model Mesh (Planned)

A unified Model Gateway routes requests to:

| Model Type | Use Case |
| --- | --- |
| Local small model | Privacy classification, extraction, sensitive summarization |
| Low-cost cloud model | Formatting, routine copy |
| Strong reasoning model | Strategy, complex research |
| Multimodal model | Web, images, documents, video |
| Coding model | Websites and prototypes |

Every call records: provider, model, cost, latency, quality, and data disclosure scope.

Automatic failover: primary provider → secondary provider → local model degradation.

## Plugin Architecture (In Progress)

The target architecture treats plugins as **untrusted by default**. Stage 1 currently implements the import-free Wasmtime Phase A path plus a pure-compute, process-local Phase B foundation for publisher verification and exact invocation binding.

- Signed manifest declaring exact permissions
- Low-risk plugins: WASM/WASI sandbox
- High-risk tools: ephemeral container or micro-VM
- No shared memory with core process
- No permanent API keys
- No arbitrary network access

## Event Sourcing (Partially Implemented)

The current audit-ledger crate implements a signed, append-only hash chain. The target architecture builds authoritative enterprise state from richer events such as:

```text
event_id, venture_id, actor_id, action, resource,
capability_id, timestamp, payload_hash, previous_event_hash,
device_signature, policy_decision_hash
```

Tamper detection exists in the current ledger prototype. Derived snapshots and recovery replay from checkpoints are planned.

## Technology Stack (Planned)

| Layer | Technology | Scope |
| --- | --- | --- |
| Sovereign Runtime | **Rust** | Vault, crypto, policy, capability tokens, audit ledger, sandbox, mesh |
| UI & SDK | **TypeScript + React + Tauri** | Desktop app, Founder Command Center, approval UI |
| Agent Workers | **Python** (isolated, untrusted) | Workflows, RAG, domain packs, evals |
| Protocols | JSON Schema, Protobuf/gRPC, WIT/WASI, MCP, A2A | Contracts, IPC, plugins, tools |

Python workers must never hold root keys or permanent permissions.

## Repository Layout (Planned)

```text
sovereign/
├── apps/          desktop, cli, demo-founder
├── crates/        kernel, vault, policy, sandbox, model-router, ...
├── packages/      sdk, contracts, plugin-sdk, ui
├── workers/       agents, evals, domain-runtime
├── packs/         founder, security, jurisdictions
├── tests/         adversarial, chaos, recovery, conformance
├── security/      threat-model, attack-trees, disclosures
├── rfcs/
└── docs/
```

## Target Comparison with Personal AI Assistants

| Personal AI Assistant | Sovereign Founder OS |
| --- | --- |
| Capability-first | Business-operation first, backed by enforceable trust boundaries |
| Chat and channel driven | Enterprise state and workflow driven |
| Model fallback | Model, node, key, data, and policy multi-layer fallback |
| Plugins may run in-process | Plugins isolated by default |
| Single gateway | Multi-node state and recovery mesh |

See [Why Not Another Agent?](docs/positioning/why-not-another-agent.md) for the full positioning.

## Further Reading

- [Distributed systems](docs/design/distributed-systems.md) — target replication, failover, and split-brain prevention design
- [THREAT_MODEL.md](THREAT_MODEL.md) — adversary model and mitigations
- [Privacy model](docs/design/privacy-model.md) — target Red/Amber/Green data zones
- [Historical Chinese project plan](docs/archive/zh/03-开源项目企划书-v0.1.md) — early design context, not a current specification
