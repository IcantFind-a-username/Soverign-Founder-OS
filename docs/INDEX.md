# Documentation Index

Complete documentation for Sovereign Founder OS. All design intent is public and version-controlled in this repository.

## Language Policy

English root docs for international contributors; complete Chinese blueprint in `docs/zh/`. See [LANGUAGE.md](LANGUAGE.md).

## Start Here

| Document | Language | Description |
| --- | --- | --- |
| [README.md](../README.md) | EN + 中文 link | Project entry point |
| [VISION.md](../VISION.md) | English | Product vision and principles |
| [ROADMAP.md](../ROADMAP.md) | English | Development stages and milestones |
| [docs/zh/README.md](zh/README.md) | 中文 | Complete design specifications |

## Architecture & Security

| Document | Description |
| --- | --- |
| [ARCHITECTURE.md](../ARCHITECTURE.md) | System architecture, six planes, agent flow |
| [THREAT_MODEL.md](../THREAT_MODEL.md) | Threat model v0.1 |
| [PRIVACY_MODEL.md](../PRIVACY_MODEL.md) | Red/Amber/Green zones, encryption, disclosure |
| [DISTRIBUTED_SYSTEMS.md](../DISTRIBUTED_SYSTEMS.md) | Replication, failover, event sourcing |
| [SECURITY.md](../SECURITY.md) | Vulnerability reporting and supply chain |
| [docs/why-not-another-agent.md](why-not-another-agent.md) | Positioning vs personal AI assistants |

## Governance & Legal

| Document | Description |
| --- | --- |
| [LICENSE](../LICENSE) | Apache License 2.0 |
| [NOTICE](../NOTICE) | Copyright and attribution |
| [TRADEMARK.md](../TRADEMARK.md) | Trademark policy |
| [GOVERNANCE.md](../GOVERNANCE.md) | Project governance |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | How to contribute |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Community standards |

## Complete Design Specifications (Chinese)

The following documents contain the full, detailed product and engineering specifications — the complete blueprint for the project:

| # | Document | Topics |
| --- | --- | --- |
| 01 | [AI Founder OS 初步设想](zh/01-AI-Founder-OS-初步设想.md) | Venture Graph, Founder Cockpit, ephemeral crews, privacy zones, v1 workflows |
| 02 | [Sovereign Founder OS 主权升级](zh/02-Sovereign-Founder-OS-主权升级.md) | Enterprise Digital Twin, jurisdiction engine, tax, security immune system, cryptography, PQC |
| 03 | [开源项目企划书 v0.1](zh/03-开源项目企划书-v0.1.md) | Full project plan: Runtime + Founder OS, OpenClaw comparison, repo layout, chaos tests, business model |
| 04 | [GUI 设计](zh/04-GUI设计.md) | Founder Cockpit, three UI modes, seven navigation areas, approval center, onboarding |

See [zh/README.md](zh/README.md) for the Chinese documentation guide.

## Document Map

```text
README.md ───────────── Entry & quick overview
    │
    ├── VISION.md ───── What and why
    ├── ARCHITECTURE.md ─ How it works
    ├── THREAT_MODEL.md ─ What we defend against
    ├── PRIVACY_MODEL.md ─ How data is protected
    ├── DISTRIBUTED_SYSTEMS.md ─ How it stays running
    ├── ROADMAP.md ───── When we build what
    │
    └── docs/zh/ ────── Complete detailed specifications (中文)
            ├── 01 产品设想
            ├── 02 主权架构
            ├── 03 开源企划书
            └── 04 界面设计
```

## RFCs

| RFC | Status | Description |
| --- | --- | --- |
| [0001 — Canonical Task Contract](../rfcs/0001-canonical-task-contract.md) | Draft | Stable task and execution envelope |
| [0002 — WASM Sandbox and Plugin Capabilities](../rfcs/0002-wasm-sandbox-and-plugin-capabilities.md) | Draft | Default-deny plugin isolation and authority model |

## Security Artifacts (Planned)

- `security/threat-model/` — versioned threat models
- `security/attack-trees/` — attack tree diagrams
- `security/disclosures/` — published advisories
