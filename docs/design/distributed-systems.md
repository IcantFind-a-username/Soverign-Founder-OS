# Distributed Systems

> **Status:** Target design. Implemented guarantees are documented in [ARCHITECTURE.md](../../ARCHITECTURE.md) and the relevant RFCs.

## Design Goal

"Distributed" in Sovereign Founder OS does not mean putting all data on a blockchain. It means:

- State exists in multiple encrypted copies
- No single permission controller
- Core services have swappable implementations
- Failures are automatically detected
- Tasks resume from checkpoints
- Node outputs can be verified by other nodes
- Single node failure does not become global failure

## Single Point of Failure Registry

This registry is public and maintained as part of the project. Each risk has a documented countermeasure.

| Single Point of Failure | Countermeasure |
| --- | --- |
| Single AI model | Multi-vendor routing + local model |
| Single model account | Independent accounts, independent vendors, local degradation |
| Single device | Encrypted replicas + recovery device |
| Single cloud vendor | Local node + second storage target + exportable backup |
| Single database | Event log + snapshots + verifiable replicas |
| Single key | Multi-device recovery + key shares |
| Single plugin marketplace | Mirrorable, offline-installable, signature-verified |
| Single official server | Core functions fully self-hosted |
| Single maintainer | Multi-maintainer approval + signed releases |
| Single legal data source | Multiple sources, versions, human review |
| Single security agent | Rules + detectors + human decisions |

## Replication Levels

| Level | Description | Production |
| --- | --- | --- |
| **L0** | Single device | Development only |
| **L1** | Local encrypted backup | Minimum production |
| **L2** | Multi-device replication (desktop, NAS, recovery device) | Recommended |
| **L3** | Blind cloud node (ciphertext only, no root key) | Optional |
| **L4** | High-assurance multi-node approval | High-value operations |

## Event Sourcing

Authoritative business state is constructed from signed, append-only events:

```text
event_id
venture_id
actor_id
action
resource
capability_id
timestamp
payload_hash
previous_event_hash
device_signature
policy_decision_hash
```

Properties:

- Nodes can rebuild state from events
- Tampering is detectable via hash chain
- Agents cannot silently delete history
- Recovery replays from last valid checkpoint
- Decisions can be proven against the information available at the time

Periodic snapshots are derived from the event chain, never authoritative on their own.

## Consistency Model

### Eventually Consistent (conflict-merge allowed)

- Drafts and notes
- Informal research
- Marketing ideas
- Todo items

Uses local-first sync with conflict resolution.

### Strongly Consistent (strict control required)

- Signed contracts
- Invoices
- Tax submissions
- Permission changes
- Fund transfers
- Key rotations
- Security incidents
- External commitments

Requires:

- Explicit write authority
- Leader lease
- Fencing token
- Idempotency key
- Version check
- Multi-node approval when configured

**Two offline nodes must not simultaneously issue conflicting fund or permission operations.**

## Automatic Failover

```text
Primary node heartbeat lost
        │
        ▼
Confirm lease has expired
        │
        ▼
Other nodes verify recent signed events
        │
        ▼
Select candidate with latest valid state
        │
        ▼
Issue new fencing token
        │
        ▼
Old node's write authority invalidated
        │
        ▼
Resume incomplete workflows
```

Simple "first node online wins" is prohibited — it causes split-brain.

## Quorum Approval Policies

Configurable per operation type:

```text
Routine email:        user approval once
Production deploy:    user + Policy Guard
Fund transfer:        user hardware key + recovery device
Root key rotation:    2-of-3 recovery shares
High-risk contract:   user + legal professional
```

A one-person company does not mean all authority on one device and one key.

## Resilient Trust Mesh (Target Design)

**Resilient Trust Mesh** names the overall cross-node trust architecture. **Recovery Mesh** is the subsystem within it that handles encrypted replication, checkpoints, failover, and recovery.

Trust nodes (not all required in Alpha):

```text
Data node ─── Key node ─── Execution node
    │              │              │
Model node ─── Policy node ─── Audit node
                    │
              Recovery node
```

Nodes cross-validate outputs. Any node can be replaced with an equivalent implementation.

## Blockchain Usage (Limited)

Blockchain is used only where it solves a real trust problem:

- Contract version existence proofs
- Audit log root anchoring
- Multi-party approval attestations
- Digital asset reconciliation

Never for: customer PII, contract full text, invoices, or identity documents.

## Recovery Requirements

Users must be able to recover without official project servers:

1. Export encrypted company data package
2. Export key recovery shares
3. Restore on a new device from backup
4. Replay event log to reconstruct state
5. Resume workflows from last checkpoint

Recovery is intended to be tested continuously via the planned Chaos CLI — see [ROADMAP.md](../../ROADMAP.md).

## Further Reading

- [ARCHITECTURE.md](../../ARCHITECTURE.md)
- [THREAT_MODEL.md](../../THREAT_MODEL.md) — T7 Split-Brain
- [Historical project plan](../archive/zh/03-开源项目企划书-v0.1.md) — Section 6 (Chinese)
