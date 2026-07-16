# RFC 0002: WASM Sandbox and Plugin Capabilities

**Status:** Draft
**Stage:** 1
**Security impact:** Critical

## Summary

Define the execution boundary for untrusted low-risk plugins. Sovereign Founder OS will run them as WebAssembly components under a default-deny host, with permissions derived from the intersection of deterministic policy, a signed capability token, a signed plugin manifest, and non-overridable sandbox ceilings.

This RFC does not make WebAssembly a universal isolation mechanism. High-risk native tools require an ephemeral container or micro-VM backend and must be rejected until that backend exists.

## Motivation

Model output and plugin code are untrusted. A prompt, plugin, or agent may request an action, but none may grant itself authority or inherit ambient access from the host process.

The Stage 1 executor began as an in-process simulation. That was useful for validating policy and capability flow, but it is not an isolation boundary. A real boundary must prove that untrusted code cannot acquire undeclared filesystem, network, environment, credential, memory, or tool access, and cannot escape resource limits.

## Non-Negotiable Invariants

1. Model suggestion is never system permission.
2. No plugin or agent can issue, approve, enlarge, revoke, or erase its own authority.
3. Missing, invalid, unsupported, or unavailable security state fails closed.
4. The effective permission set is:

   ```text
   deterministic policy decision
   ∩ signed capability token
   ∩ signed plugin manifest
   ∩ host sandbox ceilings
   ```

5. Every privileged host call is authorized separately; validating only at module startup is insufficient.
6. A capability is bound to the exact subject, venture, operation, artifact, security-relevant input, resources, approval evidence, expiry, and use limit.
7. Important execution attempts leave durable evidence, including denials, traps, timeouts, and resource exhaustion.
8. A lower-security backend is never used as a silent fallback.

## Threats in Scope

- Prompt injection causing tool misuse or data exfiltration.
- Malicious or compromised plugins.
- Module or manifest substitution after approval.
- Confused-deputy attacks where the token authorizes one resource but input targets another.
- Filesystem traversal, symlink escape, environment leakage, and ambient credentials.
- Unauthorized DNS, TCP, HTTP redirects, and DNS rebinding.
- Infinite loops, memory/table growth, output flooding, and host-call flooding.
- Cross-execution state leakage.
- Token replay, concurrent double consumption, revocation races, and process restart.
- Execution without durable intent evidence.

Sandbox escape vulnerabilities in the chosen engine remain possible. Process isolation, dependency updates, fuzzing, and rapid security patching provide defense in depth; no absolute-security claim is made.

## Execution Classes

| Risk class | Current Stage 1 foundation | Target backend |
| --- | --- | --- |
| Pure local computation | Publisher-verified import-free Core Wasm using `sovereign_core_wasm_v1`; exact V2 binding; no guest-input delivery or host effects | Wasmtime Component with reviewed WIT world |
| Low-risk constrained plugin | Denied | Wasmtime Component plus explicit capability host interfaces |
| High-risk/native tool | Denied | Ephemeral container or micro-VM |
| Unknown or undeclared | Denied | None |

## Plugin Manifest

The current foundation verifies an immutable, publisher-signed manifest containing:

```text
protocol_version
publisher_issuer
publisher_key_id
component_digest
backend = core_wasm
risk_class = pure_compute
abi = sovereign_core_wasm_v1
entrypoint = sovereign_run
requested_host_capabilities = []
operations[]
  structured tool_id, tool_version, operation_id
  strict_input_schema and limits
  JSON Pointer resource-binding rules
```

The complete installed-artifact target additionally requires:

```text
api_version
tool_id
tool_version
publisher_key_id
component_sha256
wit_world
operations[]
  operation_id
  strict_input_schema
  input_binding_rules[]
requested_host_capabilities[]
requested_limits
risk_class
local admission record and signature
```

The publisher signature establishes artifact provenance, not permission. Installation trust and runtime policy remain separate decisions. A manifest may request authority, but cannot receive more than host policy permits.

Any change to the component or manifest digest invalidates previously issued capabilities.

## Canonical Encoding and COSE_Sign1 Envelope

Every signed protocol object uses an explicit versioned body and a COSE_Sign1 envelope. The signed payload is the RFC 8785 JSON Canonicalization Scheme (JCS) encoding of the body, excluding the COSE envelope itself. The current manifest/invocation/capability profile identifier is exactly `rfc8785-jcs+sovereign-digest-v1`. Before canonicalization, parsers must enforce the protocol schema, reject duplicate object keys, reject unknown fields, enforce depth and byte limits, and reject values outside the RFC 8785/I-JSON domain. A parser must never silently keep the first or last duplicate key.

The COSE protected header contains all of the following:

- `alg` (label `1`), fixed to EdDSA (`-8`) for the first protocol version;
- `kid` (label `4`), containing the exact key identifier bytes used for role-specific trust resolution;
- `content-type` (label `3`), containing the exact versioned Sovereign media type.

These headers must be encoded in the protected header bucket. Moving any of them to the unprotected bucket, supplying a conflicting duplicate, using an unknown critical header, or selecting any other algorithm fails closed. The embedded COSE payload must byte-for-byte equal the JCS body supplied to the verifier; detached or substituted payloads are not accepted by the initial protocol.

COSE signature verification uses the standard `Signature1` structure and a non-empty, role-specific external AAD. Initial roles are:

```text
content-type                                           external AAD                              status
application/sovereign.plugin-manifest+json;v=1         sovereign:plugin-manifest:v1              implemented
application/sovereign.capability+json;v=2              sovereign:capability:v2                   implemented
application/sovereign.artifact-admission+json;v=1      sovereign:artifact-admission:v1           target
application/sovereign.audit-event+json;v=1             sovereign:audit-event:v1                  primitive only; ledger migration pending
application/sovereign.compiled-cache-record+json;v=1  sovereign:compiled-cache-record:v1        target
```

The strings above are exact UTF-8 byte sequences, with no trailing NUL or newline. A signature valid for one role must be invalid for every other role even if the JSON fields happen to be identical. COSE protected headers use deterministic CBOR encoding. Raw `serde_json` field order, pretty-printed JSON, or a signature over a digest without its role domain is not a protocol encoding.

Component identity remains the ordinary SHA-256 digest of the owned component bytes. Manifest, invocation, binding, policy, admission, and cache-record digests additionally use distinct versioned domain prefixes so that a digest from one protocol position cannot be substituted into another.

## Key Roles and Trust Resolution

Key trust is resolved by `(role, kid)`, never by `kid` alone and never by a public key carried in an untrusted object. The initial roles are publisher signing, local artifact admission, capability issuance, device audit, and compiled-cache attestation. Trusting a key for one role grants no trust in another role. Production deployments should use distinct keys for these roles; key reuse must not create implicit cross-role authority.

For the first protocol version, `kid` is the full 32-byte SHA-256 result over a versioned key-ID domain, the signing role, the Ed25519 algorithm identifier, and the canonical public-key bytes. It is never truncated. COSE carries the raw 32 bytes; JSON claims repeat it as exactly 64 lowercase hexadecimal digits. The current in-memory trust record contains issuer, status, activation/expiry, and the verifying key. Tool/venture scope, durable revocation metadata, and persistence remain target fields. Resolution is fail-closed and proceeds as follows:

1. Read `alg`, `kid`, and `content-type` only from the COSE protected header.
2. Select the trust store for the required role and look up the exact `kid`.
3. Require the protected `kid` to select the immutable local record whose identifier was recomputed from the public key at trust registration.
4. Reject unknown, disabled, revoked, not-yet-active, expired, algorithm-incompatible, or out-of-scope records.
5. Verify the COSE signature with the required content type and external AAD.
6. Require any key identifier repeated inside the signed payload to equal the protected `kid`.

A manifest publisher signature proves provenance only. It does not install the plugin, approve requested capabilities, authorize an invocation, or make the publisher a capability issuer. Installation requires a separate local admission record signed by the artifact-admission role. Key rotation creates a new `kid` and requires explicit trust and admission; it never inherits trust solely from a matching display name or tool identifier.

## Artifact Admission Transaction

Admission operates on owned immutable bytes, not on a caller-controlled path that can change between verification and execution. The complete admission boundary performs one fail-closed transaction:

1. Enforce raw manifest and artifact size ceilings before expensive parsing or compilation.
2. Read the artifact into a newly owned buffer without following an attacker-controlled symlink after validation.
3. Strictly decode and verify the manifest COSE envelope and publisher trust.
4. Compute the component digest from that owned buffer and compare its size, digest, ABI, and WIT world with the signed manifest.
5. Validate operations, schemas, bindings, risk class, requested capabilities, and requested limits against local installation policy and hard ceilings.
6. Write the verified bytes into an owner-controlled content-addressed store using exclusive temporary creation, restrictive permissions, file flush, atomic rename, and directory flush.
7. Reopen or retain the exact immutable bytes, recheck the digest, and create a locally signed admission record binding the component digest, manifest digest, effective permissions, risk class, runtime profile, and installation state.
8. Atomically publish the admission record and return an opaque `AdmittedArtifact` handle. Only this handle may enter the execution path.

If any step fails, no trusted registry entry is published. An existing content-addressed entry is reused only after its bytes are rehashed and matched; its filename is never evidence of its contents. Orphan temporary files or cache entries are untrusted and may be collected, but must never become executable through recovery or fallback logic.

The current foundation implements the in-memory portions of steps 1–5 and returns `VerifiedArtifact`: it enforces ceilings, snapshots owned bytes, verifies publisher COSE and trust state with an internal trusted clock, compares the component digest, and validates the Core Wasm manifest, operations, strict schemas, bindings, risk, and empty host-capability set. Steps 6–8—the content-addressed store, local admission signature/record, and `AdmittedArtifact` transition—are not implemented.

## Exact Invocation Binding

A plain resource string is insufficient because a tool may take a recipient, path, URL, account, or contract address from JSON input. Before authorization, the trusted host must:

1. Validate input against a strict versioned schema with unknown fields rejected where security-relevant.
2. Canonicalize the input deterministically.
3. Extract resource targets through manifest-declared JSON Pointer rules.
4. Normalize each target using a versioned host canonicalizer.
5. Create resource grants and compute input and bindings digests.
6. Include those digests and artifact digests in the signed execution claim.

External effects must use an opaque host grant. A guest-supplied target string is never authoritative after the grant is created.

The current Capability V2 claim includes:

```text
typ = sovereign.capability
version = 2
issuer and issuer_key_id
audience
subject_id and authenticated session_id
venture_id
tool_id, tool_version, and operation
component_digest
manifest_digest
canonical_input_digest
resource_bindings_digest
primary_resource
policy_decision_id and policy_digest
approval_evidence (explicitly null in the current foundation)
idempotency_key
issued_at and expires_at
max_uses = 1
risk_class = pure_compute
backend = core_wasm
canonicalization_profile = rfc8785-jcs+sovereign-digest-v1
```

Stage 1 Capability V1 tokens do not contain all these bindings. They may gate the initial import-free isolation slice, but must never authorize real host side effects. Capability V2 is necessary but not sufficient before effectful host interfaces are enabled: durable Authority Store consumption, verified approval evidence where required, crash-safe evidence ordering, local artifact admission, and reviewed host interfaces are also mandatory. The current V2 issuer rejects every approval-required request, and the validator rejects any self-supplied non-null approval evidence.

## Invocation and Cache TOCTOU Rules

Invocation preparation validates the strict schema, canonicalizes the input, extracts and normalizes bindings, and then retains the exact canonical input bytes and host-only grant commitments in an opaque `PreparedInvocation`. Capability issuance binds the digests from that object. The current verified executor compares every bound field and runs the same `VerifiedArtifact` bytes; the target effectful executor must additionally use the same locally admitted artifact handle and opaque host grants. Neither may reopen a user path, reparse a mutable caller buffer, or reconstruct security-relevant fields from guest input after authorization.

If bytes cross a process boundary, the parent sends an owned snapshot together with its expected digest and the worker rehashes it before compilation or execution. A mismatch is substitution, not a cache miss. The runtime never silently recompiles or executes a different path in-process when the requested worker or security backend is unavailable.

A compiled-cache key includes at least:

```text
component_digest
manifest_digest
engine name and exact version
engine configuration digest
compiler configuration digest
target architecture and operating-system ABI
WIT world or core ABI identifier
```

The cache record additionally binds the compiled-blob digest and is signed under the compiled-cache role. Before any unsafe engine deserialization, the worker verifies the cache-record COSE envelope, role, engine/configuration identity, target identity, and compiled bytes. A missing, mutable, unsigned, mismatched, symlinked, or poisoned cache entry is rejected and quarantined. It is never trusted because it resides under a digest-shaped filename.

The current branch has no trusted compiled cache and no killable compiler worker, so untrusted compilation remains an in-process Phase A limitation. It also has no durable Authority Store: replay/use accounting is process-local and cannot protect across restart or concurrent processes. Consequently, the V2 slice on this branch remains pure-compute only. It has no Component/WIT input ABI and no effectful host calls. Exact binding on this branch can prove authorization data relationships, but it does not make those missing execution and durability boundaries complete.

## Component Interface

The target public plugin ABI uses the WebAssembly Component Model and WIT. The world exposes only Sovereign interfaces selected for the verified manifest. It does not link the complete WASI CLI world.

Conceptually:

```wit
interface host {
    resource grant {
        invoke: func(payload: list<u8>)
            -> result<list<u8>, host-error>;
    }
}

interface plugin {
    run: func(
        context: execution-context,
        input: list<u8>,
        grants: list<borrow<grant>>
    ) -> result<list<u8>, plugin-error>;
}

world tool {
    import host;
    export plugin;
}
```

The guest never receives the capability token, root credentials, permanent API keys, or raw host resource locators.

## Default-Deny Host

Unless explicitly granted through a reviewed host interface, a plugin receives none of the following:

- environment variables or process arguments;
- host stdin, stdout, or stderr;
- filesystem directories, Home, temporary directories, sockets, or Docker control;
- DNS, TCP, UDP, HTTP, or cloud metadata endpoints;
- host clocks or randomness;
- credentials, root keys, or other plugin state;
- shared memory with the core process.

Unknown imports fail before instantiation. Unsupported manifest permissions fail installation or execution. They never cause native or in-process fallback.

## Resource Limits

Every execution gets a fresh Store and component instance. Host ceilings include:

- module/component byte size;
- linear memory and memory count;
- table elements and table count;
- instance count;
- Wasm stack size;
- deterministic fuel;
- wall-clock deadline using epoch interruption;
- canonical input and output byte size;
- guest log bytes;
- host-call count and per-call payload size.

Guest-requested limits are clamped to host ceilings. Resource exhaustion terminates execution and is auditable. A failed or trapped attempt still consumes its reserved capability use.

Fuel, Store limits, Wasm stack limits, and epoch interruption apply to guest instantiation and execution; they do not bound parsing, validation, Cranelift compilation, JIT code allocation, or all embedder memory. Those are a separate artifact-compilation threat surface. Production admission therefore requires a digest-addressed verified artifact cache, global compilation and execution concurrency budgets, and a killable resource-limited worker process. A module byte ceiling and per-runtime admission gate reduce exposure in Phase A but are not a substitute for that boundary.

Epoch interruption is a coarse, scheduler-dependent deadline. It is useful as defense in depth, not a hard real-time kill guarantee. Phase A requires `epoch_tick <= wall_timeout` and catches up delayed ticks; production hard termination and a known host-stack budget require the worker process boundary.

## Network and Filesystem

Stage 1 initially provides neither network nor filesystem interfaces.

Future filesystem access uses virtual grant handles rooted by the host, rejects symlink and traversal escape, and exposes only specific read or output capabilities. Future network access uses an egress broker that revalidates resolved IPs, redirects, TLS identity, data classification, and disclosure records on every request.

Until those brokers exist, manifests requesting filesystem or network access are rejected.

Red data can never enter a network grant. Amber disclosure requires minimization, preview, and evidence. Personal data is never written to a public blockchain.

## Authorization and Replay

The runtime uses a durable Authority Store. Validation and reservation/consumption are a single atomic operation across processes. The store tracks token status, uses, expiry, revocation, policy and approval evidence, and idempotency keys.

An unavailable Authority Store denies execution. Process-local counters are not sufficient for Capability V2.

This is a target requirement, not a claim about the current branch. Until the durable Authority Store exists, V2 tokens are restricted to pure computation with no host effects, and restart-safe or multi-process replay resistance is not claimed.

Production time comes from a trusted runtime clock. An untrusted caller cannot provide the validation timestamp.

## Audit Ordering

Execution ordering is:

```text
ExecutionRequested (hashes only)
→ durable flush
→ capability reserve/consume
→ ExecutionStarted
→ component and host calls
→ ExecutionCompleted | ExecutionFailed | ExecutionIndeterminate
```

Each external host effect has its own durable intent before the effect. If intent evidence cannot be persisted, execution is denied. If the external effect may have occurred but result evidence cannot be persisted, the outcome is `Indeterminate` and automatic retry is forbidden.

Evidence includes execution and idempotency IDs, policy/token/approval IDs, artifact and invocation digests, runtime configuration digest, resource-use metrics, host effects, result hash, and stable failure codes.

## Stable Failure Classes

Public errors distinguish:

- invalid or oversized artifact;
- invalid manifest or publisher trust;
- forbidden import or unsupported permission;
- authorization denial, replay, expiry, or revocation;
- compile or instantiate failure;
- missing or incompatible ABI;
- fuel exhaustion, deadline, memory, output, log, or host-call limit;
- guest trap;
- audit failure;
- indeterminate external effect.

Raw engine error strings are diagnostic details, not stable protocol values.

## Verification Completion Gate

Completion requires genuine malicious fixtures covering:

- environment, filesystem, network, and undeclared host imports;
- infinite loops and memory/table/output/log bombs;
- fresh-instance state isolation;
- invalid module and ABI fail-closed behavior;
- cross-domain signature reuse between manifest, capability, admission, audit, and cache roles;
- protected-header algorithm downgrade, unprotected `kid`, key-role confusion, unknown/revoked keys, and payload/header key mismatch;
- duplicate or unknown JSON fields, invalid JCS/I-JSON values, non-canonical payloads, and payload/body mismatch;
- artifact and manifest substitution before admission, after admission, and across content-addressed entries;
- exact-input substitution, resource-binding mismatch, binding-rule substitution, and mutation after capability issuance;
- cache poisoning through blob, record, engine/configuration, target, signature, filename, symlink, or digest mismatch;
- prompt injection that attempts to change grants;
- token tampering, expiry, revocation, same-process replay, restart replay, and concurrent consumption;
- failed audit intent preventing guest startup;
- trap and timeout evidence;
- V1-to-V2, worker-to-in-process, component-to-core, and high-risk-to-Wasm backend downgrade attempts.

Current tests cover the Phase A Wasm ceilings plus the implemented foundation's role separation, trust state, publisher envelope, strict/duplicate fields, artifact/manifest/input/resource substitution, immutable snapshots, canonical key-order equivalence, Capability V1/V2 separation, exact allowlists, same-process replay/idempotency, approval fail-closed behavior, Core-Wasm downgrade rejection, and guest-failure consumption. Cache poisoning, restart/cross-process replay, durable audit-intent ordering, local admission-record recovery, Component/WIT behavior, and effectful host interfaces remain completion-gate work.

## Implementation Phases

### Phase A — Import-Free Isolation Slice

- Wasmtime runtime with a fresh Store and instance per call.
- No imports or WASI capabilities.
- Module, memory, table, stack, fuel, and wall-clock limits.
- Genuine malicious Wasm tests.
- Existing in-process demo explicitly labelled simulation.

Phase A alone proves core-Wasm isolation mechanics only; it does not verify publisher or artifact identity. The separate Phase B foundation adds those checks for its V2 path, but neither path makes an output production-trusted or durably auditable. Compilation remains in-process, so Phase A is explicitly non-production. It does not complete Stage 1.

### Phase B — Verified Artifact and Invocation

- RFC 8785 payloads in role-separated COSE_Sign1 envelopes.
- Signed manifest, role-specific publisher trust store, and local admission transaction.
- Component and manifest digest binding.
- Strict input schema, canonicalization, and resource grants.
- Capability V2 exact execution claim.
- Digest-addressed compiled artifact cache and killable resource-limited compilation workers.

The current branch implements only a pure-compute, process-local subset of these requirements. It does **not** complete Phase B. A killable resource-limited compiler worker and trusted compiled cache, durable Authority Store, Component/WIT input ABI, and effectful host-call interfaces remain unimplemented. None may be represented as available through documentation, runtime flags, compatibility fallback, or a V2 token until its corresponding adversarial tests and completion gate pass.

### Phase C — Durable Authorization and Evidence

- Transactional Authority Store with revocation and cross-process replay defense.
- Crash-safe audit intent/result ordering.
- Execution receipts and stable error taxonomy.

### Phase D — Reviewed Host Interfaces

- Minimal WIT Component interface.
- One local reference tool with opaque grants.
- Per-host-call authorization and audit.
- No network or filesystem until their brokers pass adversarial review.

Stage 1 remains **In Progress** until all required phases and exit tests pass.

## External Services and Blockchain

This design requires no external API, account, wallet, or blockchain. Future public-chain use, if any, is limited to non-personal hashes, timestamps, signatures, or state commitments. It must not become the authorization source, availability dependency, or storage location for personal or business plaintext.
