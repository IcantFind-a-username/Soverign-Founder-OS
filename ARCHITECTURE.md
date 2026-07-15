# Architecture

## Overview

Sovereign Founder OS is the complete product. Its business modules share an authoritative Enterprise Graph, use the Crew Orchestrator to coordinate AI work, and rely on the Sovereign Trust Layer for controlled execution and continuity.

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

## Runtime and Trust Flow

```text
Founder Console + Product Modules
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

## Six Planes

| Plane | Responsibility |
| --- | --- |
| **Intelligence** | Models, agents, planning, reasoning |
| **Policy** | Deterministic permissions, risk, approval |
| **Execution** | Tools, browser, files, code execution |
| **Data** | Encrypted enterprise state, local storage |
| **Trust** | Identity, keys, signatures, audit, software provenance |
| **Recovery** | Replication, checkpoints, failover, disaster recovery |

## Sovereign Enterprise Graph

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

## Agent Execution Flow

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

## Crew Orchestrator

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

## Model Mesh

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

## Plugin Architecture

Plugins are **untrusted by default**.

- Signed manifest declaring exact permissions
- Low-risk plugins: WASM/WASI sandbox
- High-risk tools: ephemeral container or micro-VM
- No shared memory with core process
- No permanent API keys
- No arbitrary network access

## Event Sourcing

Authoritative state is built from signed, append-only events:

```text
event_id, venture_id, actor_id, action, resource,
capability_id, timestamp, payload_hash, previous_event_hash,
device_signature, policy_decision_hash
```

Snapshots are derived from the event chain. Tampering is detectable. Recovery replays from checkpoints.

## Technology Stack

| Layer | Technology | Scope |
| --- | --- | --- |
| Sovereign Runtime | **Rust** | Vault, crypto, policy, capability tokens, audit ledger, sandbox, mesh |
| UI & SDK | **TypeScript + React + Tauri** | Desktop app, Founder Console, approval UI |
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

## Comparison with Personal AI Assistants

| Personal AI Assistant | Sovereign Founder OS |
| --- | --- |
| Capability-first | Business-operation first, backed by enforceable trust boundaries |
| Chat and channel driven | Enterprise state and workflow driven |
| Model fallback | Model, node, key, data, and policy multi-layer fallback |
| Plugins may run in-process | Plugins isolated by default |
| Single gateway | Multi-node state and recovery mesh |

See [docs/why-not-another-agent.md](docs/why-not-another-agent.md) for the full positioning.

## Further Reading

- [DISTRIBUTED_SYSTEMS.md](DISTRIBUTED_SYSTEMS.md) — replication, failover, split-brain prevention
- [THREAT_MODEL.md](THREAT_MODEL.md) — adversary model and mitigations
- [PRIVACY_MODEL.md](PRIVACY_MODEL.md) — Red/Amber/Green data zones
- [docs/zh/03-开源项目企划书-v0.1.md](docs/zh/03-开源项目企划书-v0.1.md) — complete Chinese specification
