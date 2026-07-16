# Contributing

Thank you for your interest in Sovereign Founder OS. This project welcomes contributions from developers, security researchers, privacy engineers, and domain experts.

## Before You Start

1. Read the [README](README.md) for product scope and current status
2. Read the relevant part of [ARCHITECTURE.md](ARCHITECTURE.md)
3. Review [THREAT_MODEL.md](THREAT_MODEL.md) for security-sensitive work
4. Check [ROADMAP.md](ROADMAP.md), the relevant [RFC](rfcs/), and open issues

## Find a Useful First Contribution

Good first contributions are small, testable, and connected to the current stage. Useful starting points include:

- Reproducing a bug and adding a failing test
- Improving unclear setup, architecture, or threat-model documentation
- Adding adversarial tests for an existing security invariant
- Implementing a scoped issue whose acceptance criteria are already agreed

Open an issue before beginning a large feature or architectural change. This lets maintainers confirm scope and point you to the source-of-truth document before you invest significant time.

## How to Contribute

### Code

1. Fork the repository
2. Create a feature branch from `main`
3. Make focused changes with tests
4. Ensure CI passes (when configured)
5. Open a pull request with a clear description

### Documentation

Documentation improvements are valuable, especially:

- Threat model refinements
- Architecture RFCs
- Jurisdiction pack specifications
- Security test cases

Keep each fact in one authoritative document and link to it elsewhere instead of copying it. Clearly label proposed or target behavior so readers do not mistake it for the current implementation.

### Security Research

We actively welcome:
- Adversarial test cases
- Chaos engineering scenarios
- Agent Security Gauntlet benchmark contributions
- Threat model reviews

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Development Setup

Requires **Rust stable** ([rustup](https://rustup.rs)):

```bash
cargo test --workspace
cargo run -p sovereign-cli -- init
cargo run -p sovereign-cli -- demo
```

Planned stack beyond the secure kernel:

- TypeScript + React + Tauri (desktop UI)
- Python (isolated agent workers)

## Pull Request Guidelines

- One logical change per PR
- Include tests for security-relevant behavior
- No secrets, API keys, or credentials in commits
- Follow existing code style and naming conventions
- Reference related issues when applicable

## Security-Critical Changes

Changes to vault, policy, capability, sandbox, identity, or audit-ledger require:

- Threat model impact assessment in PR description
- Adversarial test coverage
- Dual review (once team is established)

## RFC Process

Significant architectural changes go through the `rfcs/` directory:

1. Open a draft RFC as a PR
2. Community discussion (minimum 7 days for substantial changes)
3. Maintainer acceptance or rejection with rationale
4. Implementation PR references accepted RFC

## Code of Conduct

All contributors must follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).

## Questions

Open a GitHub Discussion or Issue for questions not covered here.
