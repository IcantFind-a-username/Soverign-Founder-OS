# The Sovereign Founder OS Manifesto

> **Models are replaceable. User data is not.**

AI agents are leaving the chat box.

They can read email, change code, contact customers, operate infrastructure, handle contracts, and influence money. That makes them useful. It also makes a familiar software failure into a failure of authority.

The industry often asks: *How much autonomy can we give an agent?*

We ask a more important set of questions:

- Who gave it authority?
- Who can take that authority away?
- What evidence remains after it acts?
- Can the owner recover when the model, machine, plugin, or provider fails?

**Mutually Constrained Autonomy** is our answer. It is the constitutional design philosophy behind Sovereign Founder OS and the Sovereign Runtime beneath it.

> **Mutually Constrained Autonomy is a constitutional arrangement of humans, models, tools, policies, and recovery systems that cooperate without allowing any one of them to become the master.**

We are not against capable AI. We are against invisible, permanent, and unrecoverable authority.

## Intelligence Is Not Trust

A model can be intelligent without being reliable. It can be helpful without being accountable. It can follow the wrong instruction perfectly.

High-privilege agents operate in a world of prompt injection, poisoned context, compromised dependencies, ambiguous intent, provider outages, policy changes, software defects, and ordinary mistakes. None of these require a malicious superintelligence. A plausible answer combined with excessive permission is enough.

Trust therefore cannot come from a model saying that it is safe, from a system prompt telling it to behave, or from a vendor calling it aligned.

Prompts are instructions, not security boundaries.

A model may propose an action. It must not be able to grant itself the permission required to perform that action. It must not be able to execute a sensitive action and then erase or rewrite the evidence. It must not receive the full keys to a business merely because it is convenient.

**AI must not authorize itself.**

## Continuity Cannot Be Rented from One Provider

A company is more than the model currently serving it. It is its customer history, contracts, decisions, credentials, workflows, evidence, and ability to continue tomorrow.

If one model change can break every workflow, the model is a single point of failure. If one cloud account can remove access to company state, the platform is a single point of failure. If one official server is required for recovery, the owner is not sovereign. If one plugin can reach every secret, isolation has already failed.

Convenient dependencies are still dependencies. Providers can experience outages, change prices, alter policies, withdraw models, restrict jurisdictions, or disappear. A serious operating system must expect components to fail and make replacement a normal operation rather than a catastrophe.

Sovereignty does not mean refusing every cloud service. It means retaining the practical ability to inspect, export, replace, revoke, and recover without asking a platform for permission.

**Models are replaceable. User data is not.**

## Mutually Constrained Autonomy

We reject the choice between powerless assistants and all-powerful agents.

Our alternative is **Mutually Constrained Autonomy**: useful autonomy created through separation of powers.

Planning, authorization, execution, auditing, recovery, and ownership are distinct responsibilities. A Planner can propose. A Policy Guard can permit within explicit rules. An Executor can act only within granted capability. An Auditor can preserve evidence. A Recovery Controller can restore valid state. The Human Owner defines the ultimate boundaries and can revoke authority.

No participant should be able to propose a sensitive action, approve it, execute it, declare it successful, and destroy the evidence alone.

This is not autonomy by blind trust. It is autonomy made possible by limits.

## Our Principles

### 1. Models are replaceable. User data is not.

Business state must outlive any model, vendor, API, or orchestration framework. Models consume portable contracts and authorized context; they do not become the canonical home of the company.

### 2. Authority must expire.

Permission should be narrow, time-bound, resource-bound, purpose-bound, and revocable. Standing privilege turns yesterday's approval into tomorrow's breach.

### 3. AI must not authorize itself.

The component requesting power cannot be the sole component granting it. Sensitive authority must come from independently enforced policy, explicit human approval, or both.

### 4. Autonomy must be mutually constrained.

No model, agent, plugin, server, or operator should hold every critical power. Separation of duties is not bureaucratic overhead; it is the architecture that makes meaningful autonomy possible.

### 5. There must be no single point of failure.

Model failure, node failure, key loss, data corruption, policy failure, and provider revocation require distinct recovery paths. Redundancy is incomplete when every fallback depends on the same control plane.

### 6. Local-first means user-controlled.

The owner should control the authoritative state, encryption keys, exports, and recovery material. Cloud services may extend the system, but they must not become the only doorway to the owner's company.

### 7. Plugins are untrusted by default.

Installed does not mean trusted. Popular does not mean safe. Official does not mean infallible. Plugins, tools, external content, and model output must receive only the minimum access their declared task requires.

### 8. Policy is code, not a prompt.

Security rules must be deterministic, inspectable, testable, versioned, and enforced outside the model. Natural-language explanations can help people understand a decision; they cannot replace the mechanism that enforces it.

### 9. Every important action leaves evidence.

Sensitive actions must produce durable, tamper-evident, human-understandable records: what was requested, what policy allowed it, what authority was used, what changed, and what result followed. Logs are not decoration. They are part of accountability and recovery.

### 10. Recovery comes before autonomy.

Before a system is allowed to act more freely, it must prove that the owner can stop it, restore valid state, rotate compromised authority, and continue without the failed component. An action that cannot be recovered from deserves a higher threshold than one that can.

### 11. Security is not a premium feature.

Core isolation, permission enforcement, local ownership, export, audit, and recovery must not be held hostage by a subscription. Paid services may offer convenience and managed infrastructure; they must not own the user's sovereignty.

### 12. We will not claim absolute security.

Every system has assumptions, defects, and limits. We will describe ours. Security claims should be tied to public threat models, reproducible tests, disclosed failures, and evidence that others can challenge.

## What We Commit To

We will design for the owner's right to exit.

We will prefer open contracts and replaceable components over hidden lock-in. We will keep the critical local runtime usable without official servers. We will treat model output, plugins, remote services, and imported content as constrained inputs rather than sources of authority. We will make high-risk actions visible and revocable. We will publish the boundaries of what has and has not been proven.

We will not trade away these principles merely to make a demo look more autonomous.

When convenience and sovereignty conflict, the user must be shown the tradeoff. When automation and recoverability conflict, recovery comes first. When a security claim cannot be demonstrated, it must be presented as an aspiration rather than a fact.

## How to Judge Us

Do not judge Sovereign Founder OS by the number of agents in a demo. Ask instead:

- Can the owner replace the model without losing the company?
- Can a permission be understood, limited, and revoked?
- Can a malicious plugin reach anything it was not explicitly granted?
- Can an important decision be reconstructed from evidence?
- Can the system recover without an official server?
- Can the owner export their state and keys in usable form?
- Can a failed component be removed without collapsing the whole system?
- Are security limitations stated as clearly as security features?

These questions turn a manifesto into an engineering standard.

## The Future We Want

We want AI that expands human agency without quietly absorbing human authority.

We want founders and small teams to benefit from powerful automation without surrendering their company to a model provider, cloud account, plugin marketplace, or opaque orchestration layer.

We want systems that continue when components fail, explain themselves when actions matter, and return control when the owner demands it.

The goal is not an agent that can do everything.

The goal is a company that remains yours while agents help operate it.

> **Your company. Your data. Your keys.**
>
> **Built on many models. Dependent on none.**

---

This manifesto states the project's position and non-negotiable principles. Technical architecture, threat analysis, implementation decisions, and delivery status belong in the [Architecture](ARCHITECTURE.md), [Threat Model](THREAT_MODEL.md), [RFCs](rfcs/), and [Roadmap](ROADMAP.md). A dedicated technical whitepaper will connect those mechanisms into a complete argument.
