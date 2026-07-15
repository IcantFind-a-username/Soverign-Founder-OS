# Sovereign Founder OS

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Stage](https://img.shields.io/badge/Stage-1%20Secure%20Kernel-orange)](ROADMAP.md)

> **Build and run your one-person company with AI—without giving up control of your data, decisions, or business.**

**Sovereign Founder OS** is an early-stage open-source AI operating system being built to help anyone start and run a one-person business while keeping their data, decisions, and business continuity under their control.

**[中文完整设计文档 →](docs/zh/README.md)**

---

## From Idea to Operating Business

The product vision guides a founder through the whole business loop, without requiring them to configure agents or understand software infrastructure:

```text
Understand the founder and their strengths
  → Find a viable business direction
  → Choose customers and validate their problems
  → Design the offer, product, and pricing
  → Decide today's most important work
  → Assemble an AI crew and execute
  → Win customers and collect feedback
  → Manage delivery, contracts, revenue, and risk
  → Improve the company continuously
```

Users see goals, decisions, approvals, progress, and the next action—not agent parameters, token counts, or tool schemas.

## Planned Product System

| Module | What it is designed to help the founder do |
| --- | --- |
| **Venture Studio** | Discover opportunities, validate customer problems, choose a business model, position an offer, and design pricing experiments |
| **AI Crew** | Bring together product, research, development, design, marketing, sales, support, finance, legal, and security roles for the task at hand |
| **Product & Delivery** | Build websites, prototypes, software, content, client deliverables, plans, and repeatable services |
| **Customers & Growth** | Define customers, manage leads and CRM, create campaigns and proposals, follow up, sell, and learn from feedback |
| **Finance, Legal & Tax** | Track income, expenses, invoices, cash flow, tax reserves, contracts, obligations, and professional escalation needs |
| **Founder Command Center** | Show company stage, current risks, key metrics, pending approvals, unvalidated assumptions, and the three most important next actions |
| **Sovereign Trust Layer** | Keep data, permissions, evidence, model choice, recovery, and the founder's right to exit under user control |

The **Sovereign Enterprise Graph** will be the structured source of truth beneath these modules: the founder, products, customers, projects, contracts, invoices, knowledge, metrics, risks, and decisions—not a pile of chat history.

## Why Sovereign

Business automation becomes dangerous when a model, plugin, cloud account, or platform can quietly become the owner. Sovereign Founder OS is designed so that useful AI assistance does not require that surrender:

- Data and authoritative business state must remain user-controlled and portable
- The system is designed to be local-first and independent of any one model or provider
- AI must not grant itself authority; important actions must require independently enforced policy and, when needed, human approval
- Plugins and external content must be treated as untrusted by default
- Important actions must leave tamper-evident, understandable evidence
- Workflows are designed to recover from model, process, node, and provider failure
- Core security, export, audit, and recovery will not be premium-only features
- Security limitations must be stated openly; the project will not claim absolute security

> **Defining demo target:** Kill the model, the server, and the plugin. **The company keeps running.**

Read the **[Sovereign Founder OS Manifesto →](MANIFESTO.md)** for the principles we will not compromise.

## One Product, Clear Names

| Name | Role |
| --- | --- |
| **Sovereign Founder OS** | The complete product and the project's only primary brand |
| **AI Crew** | The user-facing team of AI roles assembled for a business goal |
| **Crew Orchestrator** | The internal subsystem that selects, constrains, coordinates, and dissolves each AI crew |
| **Sovereign Trust Layer** | The cross-cutting product layer for privacy, authority, audit, resilience, and data sovereignty |
| **Sovereign Runtime** | The underlying local-first, model-neutral runtime that implements the Trust Layer and controlled execution |
| **Sovereign Founder OS Manifesto** | The project's public position and non-negotiable principles |

### Core Concepts

| Concept | Description |
| --- | --- |
| **Enterprise Graph** | Structured digital twin of the company — not chat history |
| **Mutually Constrained Autonomy** | Planner, Policy Guard, Executor, Auditor, Recovery Controller, Human Owner — no single node holds all power |
| **Capability Tokens** | Short-lived, scoped, revocable execution permissions |
| **Resilient Trust Mesh** | Multi-node encrypted replication with automatic failover |

## Documentation

### Recommended Reading Path

[README](README.md) → [MANIFESTO](MANIFESTO.md) → `WHITEPAPER` *(planned)* → [ARCHITECTURE](ARCHITECTURE.md) → [THREAT MODEL](THREAT_MODEL.md) → [RFCs](rfcs/) → [ROADMAP](ROADMAP.md) → `DEMO` *(planned)*

### Quick Start (English)

| Document | Description |
| --- | --- |
| [MANIFESTO.md](MANIFESTO.md) | The Sovereign Founder OS position and non-negotiable principles |
| [VISION.md](VISION.md) | Product vision and design principles |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threat model v0.1 |
| [PRIVACY_MODEL.md](PRIVACY_MODEL.md) | Privacy and data classification |
| [ROADMAP.md](ROADMAP.md) | Development roadmap (Stage 0–7) |
| [docs/INDEX.md](docs/INDEX.md) | Full documentation map |

### Complete Blueprint (中文)

All detailed design specifications are public in [`docs/zh/`](docs/zh/):

- [01 — 产品设想](docs/zh/01-AI-Founder-OS-初步设想.md)
- [02 — 主权架构升级](docs/zh/02-Sovereign-Founder-OS-主权升级.md)
- [03 — 开源企划书 v0.1](docs/zh/03-开源项目企划书-v0.1.md)
- [04 — GUI 设计](docs/zh/04-GUI设计.md)

## Tech Stack (Planned)

| Layer | Technology |
| --- | --- |
| Sovereign Runtime | Rust |
| Desktop UI | TypeScript + React + Tauri |
| Agent Workers | Python (isolated, untrusted boundary) |
| Protocols | JSON Schema, gRPC, WASI, MCP, A2A |

## Current Status

**Stage 1: Secure Kernel** — in active development.

```text
crates/
  contracts/      shared types (events, tokens, policy)
  identity/       device keys and signing
  audit-ledger/   append-only signed event log
  policy/         deterministic permission engine
  capability/     short-lived execution tokens
  vault/          local encrypted storage
  sandbox/        isolated tool execution (stub)
apps/
  cli/            sovereign CLI
```

Run locally:

```bash
cargo test --workspace
cargo run -p sovereign-cli -- init
cargo run -p sovereign-cli -- demo
```

See [ROADMAP.md](ROADMAP.md) for the full development plan.

## Contributing

We welcome contributions from agent framework developers, security researchers, privacy engineers, and founders. See [CONTRIBUTING.md](CONTRIBUTING.md).

Report security issues via [SECURITY.md](SECURITY.md) — do not open public issues for vulnerabilities.

## License & Intellectual Property

- **Code and documentation:** [Apache License 2.0](LICENSE)
- **Attribution:** [NOTICE](NOTICE)
- **Trademarks:** [TRADEMARK.md](TRADEMARK.md) — "Sovereign Founder OS" and related marks are protected

You are free to use, modify, and distribute this project under Apache 2.0 terms. Forks must retain license and attribution notices. Trademark use requires compliance with our trademark policy.

## Links

- Repository: https://github.com/IcantFind-a-username/Sovereign-Founder-OS
- Documentation index: [docs/INDEX.md](docs/INDEX.md)
- Why not another agent?: [docs/why-not-another-agent.md](docs/why-not-another-agent.md)

---

<p align="center">
  <strong>Built on many models. Dependent on none.</strong><br>
  <strong>Protected by cryptography. Controlled by the founder.</strong>
</p>
