# Documentation

This page helps contributors find the current source of truth without reading the whole repository.

## Core Reading Path

| Document | Answers |
| --- | --- |
| [README](../README.md) | What is the product, who is it for, and what exists today? |
| [MANIFESTO](../MANIFESTO.md) | Which principles will the project not trade away? |
| [ARCHITECTURE](../ARCHITECTURE.md) | How is the current implementation structured? |
| [THREAT MODEL](../THREAT_MODEL.md) | What are the assets, attackers, boundaries, and defenses? |
| [ROADMAP](../ROADMAP.md) | What is being built now and what comes later? |
| [RFCs](../rfcs/) | What does each concrete design propose or specify? |

`WHITEPAPER.md` will join this path when a technical whitepaper exists. Until then, architecture, threat model, and RFCs are the technical sources of truth.

## Choose by Task

| If you want to… | Start here |
| --- | --- |
| Make a first contribution | [CONTRIBUTING.md](../CONTRIBUTING.md) and current open issues |
| Understand product direction | [README.md](../README.md) and [MANIFESTO.md](../MANIFESTO.md) |
| Change runtime architecture | [ARCHITECTURE.md](../ARCHITECTURE.md) and the relevant [RFC](../rfcs/) |
| Review security | [THREAT_MODEL.md](../THREAT_MODEL.md), [SECURITY.md](../SECURITY.md), and [RFC 0002](../rfcs/0002-wasm-sandbox-and-plugin-capabilities.md) |
| Study privacy or resilience targets | [Privacy model](design/privacy-model.md) and [Distributed systems](design/distributed-systems.md) |
| Discuss product UI | [GUI design draft](product/gui-design.zh-CN.md) (Chinese) |
| Understand the category positioning | [Why Not Another Agent?](positioning/why-not-another-agent.md) |
| Trace how the idea evolved | [Historical Chinese design archive](archive/zh/README.md) |

## Document Status

- **Current:** describes code or policy that exists now. Architecture must make this explicit.
- **Target:** describes intended behavior that is not fully implemented. Design notes and draft RFCs use this label.
- **Historical:** preserves earlier reasoning but is not a current specification.

If documents conflict, current implementation plus accepted RFCs take precedence, followed by the core documents above. Historical material is context only.

## Community and Project Policy

- [Contributing](../CONTRIBUTING.md)
- [Governance](../GOVERNANCE.md)
- [Code of Conduct](../CODE_OF_CONDUCT.md)
- [Security reporting](../SECURITY.md)
- [Language policy](LANGUAGE.md)
- [License](../LICENSE), [Notice](../NOTICE), and [Trademark policy](../TRADEMARK.md)

## Current RFCs

| RFC | Status | Topic |
| --- | --- | --- |
| [0001](../rfcs/0001-canonical-task-contract.md) | Draft | Canonical task contract |
| [0002](../rfcs/0002-wasm-sandbox-and-plugin-capabilities.md) | Draft; partially implemented | WASM sandbox and plugin capabilities |
| [0003](../rfcs/0003-signed-approval-evidence.md) | Draft; foundation implemented | Signed human approval evidence |
