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

| Risk class | Backend | Stage 1 behavior |
| --- | --- | --- |
| Pure local computation | Wasmtime Component, no host effects | Allowed after full verification |
| Low-risk constrained plugin | Wasmtime Component plus explicit capability host interfaces | Added incrementally per reviewed interface |
| High-risk/native tool | Ephemeral container or micro-VM | Denied until backend exists |
| Unknown or undeclared | None | Denied |

## Plugin Manifest

The installed artifact must have an immutable signed manifest. The minimum target schema is:

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
signature
```

The publisher signature establishes artifact provenance, not permission. Installation trust and runtime policy remain separate decisions. A manifest may request authority, but cannot receive more than host policy permits.

Any change to the component or manifest digest invalidates previously issued capabilities.

## Exact Invocation Binding

A plain resource string is insufficient because a tool may take a recipient, path, URL, account, or contract address from JSON input. Before authorization, the trusted host must:

1. Validate input against a strict versioned schema with unknown fields rejected where security-relevant.
2. Canonicalize the input deterministically.
3. Extract resource targets through manifest-declared JSON Pointer rules.
4. Normalize each target using a versioned host canonicalizer.
5. Create resource grants and compute input and bindings digests.
6. Include those digests and artifact digests in the signed execution claim.

External effects must use an opaque host grant. A guest-supplied target string is never authoritative after the grant is created.

The target execution claim includes:

```text
protocol_version
subject and authenticated session
venture_id
tool_id and version
operation_id
component_digest
manifest_digest
canonical_input_digest
resource_bindings_digest
policy_decision_id and policy_digest
approval_evidence_id when required
idempotency_key
issued_at and expires_at
max_uses
```

Stage 1 Capability V1 tokens do not contain all these bindings. They may gate the initial import-free isolation slice, but must never authorize real host side effects. Capability V2 is required before effectful host interfaces are enabled.

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

## Verification

CI uses genuine malicious Wasm fixtures covering:

- environment, filesystem, network, and undeclared host imports;
- infinite loops and memory/table/output/log bombs;
- fresh-instance state isolation;
- invalid module and ABI fail-closed behavior;
- artifact and manifest substitution;
- exact-input and resource-binding mismatch;
- prompt injection that attempts to change grants;
- token expiry, revocation, restart replay, and concurrent consumption;
- failed audit intent preventing guest startup;
- trap and timeout evidence;
- high-risk tools refusing Wasm downgrade.

## Implementation Phases

### Phase A — Import-Free Isolation Slice

- Wasmtime runtime with a fresh Store and instance per call.
- No imports or WASI capabilities.
- Module, memory, table, stack, fuel, and wall-clock limits.
- Genuine malicious Wasm tests.
- Existing in-process demo explicitly labelled simulation.

This proves core-Wasm isolation mechanics only. It is not yet the Component/WIT plugin ABI, does not verify publisher or artifact identity, and does not make an output production-trusted or durably auditable. Compilation remains in-process, so Phase A is explicitly non-production. It does not complete Stage 1.

### Phase B — Verified Artifact and Invocation

- Signed manifest and publisher trust store.
- Component and manifest digest binding.
- Strict input schema, canonicalization, and resource grants.
- Capability V2 exact execution claim.
- Digest-addressed compiled artifact cache and killable resource-limited compilation workers.

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
