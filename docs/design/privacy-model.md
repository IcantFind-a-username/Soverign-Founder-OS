# Privacy Model

> **Status:** Target design. Implemented guarantees are documented in [ARCHITECTURE.md](../../ARCHITECTURE.md) and the relevant RFCs.

## Design Philosophy

We do not claim "absolute security." We pursue:

- **Privacy by design**
- **Local-first**
- **Server-blind by default**
- **End-to-end encrypted sync** (where applicable)
- **Verifiable security**
- **No single point of failure**

Credibility comes from public threat models, code, tests, and audits — not adjectives.

## Data Classification

### Red Zone — Never Leaves User-Controlled Device

- Root and company master keys
- Government ID documents
- Complete customer lists
- Bank credentials and full financial records
- API secrets
- Full private email content
- Original contract documents
- Unpublished trade secrets

**Rule:** Red-zone tasks use local models and local tools only.

### Amber Zone — Processed Before Cloud Use

- De-identified customer requirements
- Anonymized business metrics
- Email content with names removed
- Document excerpts with minimum necessary fields

**Rule:** Local Privacy Gateway de-identifies data. User sees a preview of "what will be sent to the model" before transmission.

### Green Zone — Approved for Cloud Models

- Public market research
- Generic copywriting prompts
- Published product information
- Research questions without personal identifiers

## Data Disclosure Record

Every cloud model call generates a record:

```text
provider          — which vendor received the request
model             — which model was used
fields_sent       — which data fields were included
classification    — Red / Amber / Green
purpose           — why the transmission was necessary
retention_policy  — provider retention terms
policy_approval   — which policy rule authorized the call
timestamp         — when the call occurred
```

Users can review disclosure history in the Founder Command Center.

## Encryption Architecture

### Envelope Encryption

```text
User Root Key
 └── Company Key
      └── Project Key
           ├── Database Key
           ├── File Key
           ├── Backup Key
           └── Audit Signing Key
```

Requirements:

- Each company is cryptographically isolated
- Each project is cryptographically isolated
- Keys support rotation without data loss
- Revoked devices cannot decrypt new data
- Cloud never holds the complete root key
- Recovery does not depend on official project servers
- Only audited cryptographic libraries — no custom algorithms

### Identity vs. Encryption Keys

- **Authentication:** WebAuthn / Passkey
- **Encryption:** Separate key hierarchy

Login compromise must not directly enable data decryption.

## Local-First Storage

- All enterprise data stored in local encrypted Vault by default
- Cloud stores ciphertext only (Level 3: blind cloud node)
- Multi-device sync is end-to-end encrypted
- User can export all data and recovery package offline

## Zero Trust Access

No agent, plugin, or tool is trusted by default — regardless of whether it is "official," "local," or "user-installed."

Every access is evaluated for:

```text
subject       — who is requesting
action        — what operation
resource      — what is being accessed
classification — data sensitivity level
device_trust  — is this device authorized
token_valid   — is the capability token current
risk_level    — computed risk score
approval      — is human approval required
```

## High-Risk Actions (Never Silent)

These operations always require explicit human approval:

- Send email or direct messages
- Publish web or social media content
- Delete files
- Deploy code
- Modify production data
- Sign contracts
- Place orders or payments
- Create ad spend
- Make commitments to customers

The system generates previews and diffs. The user signs the final decision.

## Blockchain and Personal Data

**Personal data is never written to public blockchains.**

```text
Off-chain:  encrypted contracts, customer data, invoices
On-chain:   hashes, timestamps, signatures, state commitments
```

Deleting off-chain ciphertext or destroying keys renders on-chain records non-restorable.

## Crypto Agility

- Ciphertext records algorithm version
- Keys and algorithms are separable
- Support key rotation and batch re-encryption
- Support hybrid classical + post-quantum (PQC) transition
- NIST PQC standards (ML-KEM, ML-DSA, SLH-DSA) planned for long-lived data

## User-Facing Privacy Indicator

Every AI task displays its privacy mode:

```text
Privacy: Local only
```

or

```text
Privacy: Cloud-assisted
2 anonymized fields will be shared
```

Clicking reveals: recipient, content, purpose, retention, model used, and local-only alternative if available.

## What We Do Not Promise

- Never leaks
- Absolutely secure
- Unbreakable
- 100% legally correct in all jurisdictions

## Further Reading

- [THREAT_MODEL.md](../../THREAT_MODEL.md)
- [ARCHITECTURE.md](../../ARCHITECTURE.md)
- [Historical sovereignty design](../archive/zh/02-Sovereign-Founder-OS-主权升级.md) (Chinese)
