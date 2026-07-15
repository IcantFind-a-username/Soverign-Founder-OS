# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Sovereign Founder OS, please report it responsibly.

**Do not** open a public GitHub issue for security vulnerabilities.

### How to Report

1. Open a private security advisory via GitHub: [Security Advisories](https://github.com/IcantFind-a-username/Sovereign-Founder-OS/security/advisories/new)
2. Or email the maintainers (contact to be published when advisory email is configured)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- Acknowledgment within 72 hours
- Status update within 7 days
- Coordinated disclosure timeline agreed with reporter
- Credit in advisory (unless you prefer anonymity)

## Supported Versions

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Previous minor | Security fixes only |
| Pre-Alpha / main branch | Best effort |

## Security Requirements for Contributors

All pull requests affecting security-critical code must:

- Pass static analysis
- Pass secret scanning
- Pass dependency vulnerability scan
- Include tests for security-relevant behavior
- Receive review from a security code owner (when team is established)

Security-critical paths (Rust core):
- `crates/vault/`
- `crates/policy/`
- `crates/capability/`
- `crates/audit-ledger/`
- `crates/sandbox/`
- `crates/identity/`

Changes to these paths require dual review once the team grows beyond one maintainer.

## Supply Chain Security

Releases include:

- SHA-256 checksums
- SBOM (Software Bill of Materials)
- Signed binaries and containers (Sigstore)
- Build provenance (SLSA-aligned)
- Source commit reference
- Reproducible build instructions

## Security Testing

Public adversarial and chaos tests are a core project deliverable:

```text
sovereign chaos kill-model
sovereign chaos revoke-provider
sovereign chaos kill-primary-node
sovereign chaos corrupt-replica
sovereign chaos inject-malicious-skill
sovereign chaos expire-token
sovereign chaos simulate-data-exfiltration
sovereign chaos restore
```

See [THREAT_MODEL.md](THREAT_MODEL.md) and [ROADMAP.md](ROADMAP.md) Stage 5.

## Scope

In scope:
- Sovereign Agent Runtime core
- Founder OS application
- Official plugins and packs distributed by this project

Out of scope:
- Third-party model provider security
- User misconfiguration of cloud API keys
- Attacks requiring physical access to an unlocked, authenticated device

## Further Reading

- [THREAT_MODEL.md](THREAT_MODEL.md)
- [PRIVACY_MODEL.md](PRIVACY_MODEL.md)
- [security/](security/) — attack trees and disclosures (as published)
