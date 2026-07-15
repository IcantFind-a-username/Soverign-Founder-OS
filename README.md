# Sovereign Founder OS

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Stage](https://img.shields.io/badge/Stage-1%20Secure%20Kernel-orange)](ROADMAP.md)

> **Your company. Your data. Your keys.**
> **Many models. No master. No single point of failure.**

**[中文完整设计文档 →](docs/zh/README.md)**

---

Sovereign is a **local-first, model-neutral, jurisdiction-aware** AI operating system for one-person companies, independent developers, small consultancies, and Micro-SaaS founders.

It is built in two layers:

1. **Sovereign Agent Runtime** — a reusable secure runtime (model routing, sandboxing, encrypted vault, policy engine, audit ledger)
2. **Founder OS** — a reference application proving the runtime works for real business operations

```text
• No model lock-in
• No trusted plugins
• No single point of failure
• Encrypted local ownership
• Verifiable permissions
• Recoverable workflows
```

## Why This Exists

When a single AI provider, cloud vendor, or platform fails — or revokes access — a business built on that dependency can stop overnight. Sovereign Founder OS ensures that **your data, keys, and business state remain yours**, and your company keeps running even when components fail.

> We killed the model, the server and the plugin. **The company kept running.**

Read **[The Sovereign Crew Manifesto →](MANIFESTO.md)** for the principles we will not compromise.

## How It Works

Users describe what they want to achieve. The system handles the rest:

```text
Clarify goals → Analyze opportunity → Generate venture plan
→ Assemble AI crew → Execute tasks → Deliver artifacts
→ Collect feedback → Update strategy → Show next action
```

Users see **what to do next** — not agent parameters, token counts, or tool schemas.

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
| [MANIFESTO.md](MANIFESTO.md) | The Sovereign Crew position and non-negotiable principles |
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
| Secure Core | Rust |
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
  sandbox/        default-deny Wasmtime isolation (Phase A)
apps/
  cli/            sovereign CLI
```

Run locally:

```bash
cargo test --workspace
cargo run -p sovereign-cli -- init
cargo run -p sovereign-cli -- sandbox-check
cargo run -p sovereign-cli -- demo
```

The isolated path currently permits import-free pure computation only. Environment, filesystem, network, WASI, and every other host import are denied. `sandbox-check` is a mechanical Phase A check using an ephemeral test issuer—not a production trust anchor. Artifact compilation is still in-process and is not covered by guest fuel or Store limits. The effectful tool step in `demo` remains explicitly labelled as a simulation until signed manifests, exact invocation binding, bounded compilation workers, durable authorization, and audited host interfaces are implemented. See [RFC 0002](rfcs/0002-wasm-sandbox-and-plugin-capabilities.md).

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
