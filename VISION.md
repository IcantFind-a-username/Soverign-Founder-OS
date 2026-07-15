# Vision

## What We Are Building

**Sovereign Founder OS is an AI operating system that helps anyone start and run a one-person business, while keeping their data, decisions, and business continuity under their control.**

It is built for ordinary people, solo founders, freelancers, independent developers, small consultancies, and Micro-SaaS founders. A user should not need an entrepreneurship background, a technical team, or knowledge of agent frameworks. The system turns an uncertain starting point into a guided path for building and operating a real company.

It is not a chatbot with business features bolted on, and it is not primarily a security-runtime product. It is the company's digital operating center: structured business state, coordinated work, decisions, approvals, deliverables, customers, finances, obligations, evidence, and next actions.

## Brand Promise

> **Build and run your one-person company with AI—without giving up control of your data, decisions, or business.**

中文：

> **用 AI 建立和经营属于你自己的一人公司，同时不放弃对数据、决策和企业的控制权。**

## The Founder Journey

```text
Who I am and what I can do
  → What business fits me
  → Which customers I should serve
  → What product or service to offer and how to price it
  → What matters most today
  → AI crew executes approved work
  → Customers, sales, delivery, and feedback
  → Contracts, income, costs, tax, compliance, and risk
  → Continuous improvement
```

The user confirms goals, boundaries, and consequential decisions. The system handles internal complexity and presents understandable results, risks, approvals, and next actions.

## Product System

| Module | Scope |
| --- | --- |
| **Venture Studio** | Founder profile, skills and resources, opportunity research, customer validation, business model, positioning, pricing, and experiments |
| **AI Crew** | Task-specific product, research, development, design, marketing, sales, support, finance, legal, and security roles |
| **Product & Delivery** | Websites, prototypes, software, content, project plans, client delivery, quality, releases, and standardized services |
| **Customers & Growth** | Customer profiles, lead discovery, CRM, outreach, proposals, content, social media, sales pipeline, support, and feedback |
| **Finance, Legal & Tax** | Income, expenses, invoices, cash flow, tax reserves and reminders, contract drafts, privacy, IP, compliance, and professional escalation |
| **Founder Command Center** | Company stage, operating metrics, risks, pending approvals, completed work, unresolved assumptions, and daily priorities |
| **Sovereign Trust Layer** | Privacy, model neutrality, constrained authority, audit, encrypted storage, sandboxing, recovery, portability, and business continuity |

The product hierarchy is intentionally explicit:

```text
Sovereign Founder OS
├── Venture Studio
├── AI Crew
│   └── Crew Orchestrator
├── Product & Delivery
├── Customers & Growth
├── Finance / Legal / Tax
├── Founder Command Center
└── Sovereign Trust Layer
    └── Sovereign Runtime
        ├── Model Mesh
        ├── Policy Engine
        ├── Secure Vault
        ├── Audit Ledger
        ├── Tool Sandbox
        └── Recovery Mesh
```

## Naming Boundaries

| Name | Meaning |
| --- | --- |
| **Sovereign Founder OS** | The complete product, repository, community, and only primary brand |
| **AI Crew** | A user-facing product module: the AI team working toward a founder's goal |
| **Crew Orchestrator** | The internal coordination subsystem that assembles, constrains, and dissolves crews |
| **Sovereign Trust Layer** | The product's cross-cutting design commitments for control, privacy, evidence, and continuity |
| **Sovereign Runtime** | The reusable technical foundation implementing controlled execution and the Trust Layer |
| **Sovereign Founder OS Manifesto** | The project's position, principles, and long-term commitments |

There is no separate crew brand. Product copy uses **AI Crew** for the user-visible capability and **Crew Orchestrator** for the internal component.

## The Problem

Starting a business requires decisions and execution across market research, product design, delivery, sales, customer relationships, finance, contracts, tax, and compliance. Today this knowledge is fragmented across tools and specialists. General AI chat can give advice, but it does not maintain a coherent, recoverable operating state for a company or reliably carry work from idea to outcome.

Once AI can touch email, code, contracts, customer records, credentials, and money, convenience also creates concentrated authority. A provider outage, account revocation, malicious plugin, excessive permission, or corrupted workflow can interrupt or compromise the business.

Sovereign Founder OS addresses both problems: it helps the founder operate the company, while its local-first, model-neutral, recoverable architecture keeps control and continuity with the founder.

## Development Order Is Not Product Identity

Engineering begins with the **Sovereign Runtime secure kernel** because trustworthy business automation depends on enforceable permissions, durable evidence, isolation, and recovery. Each infrastructure stage must then be proven through real Founder OS workflows.

The complete product is **Sovereign Founder OS**. The Runtime is its reusable technical foundation, not a separate primary product.

## Core Design Principles

### 1. State Over Conversation

The system maintains a **Sovereign Enterprise Graph** — a structured digital twin of the company — not a pile of chat logs. Every AI action must change enterprise state, produce verifiable artifacts, and leave an auditable record.

### 2. Mutually Constrained Autonomy

No single agent or component may simultaneously: decide goals, grant permissions, access full data, execute actions, delete records, and approve results.

Roles are separated: Planner, Policy Guard, Executor, Auditor, Recovery Controller, Human Owner.

> No node can initiate a sensitive action, approve it, and destroy the evidence.

### 3. Sovereignty

Users own their data, keys, model choices, asset controls, and business continuity. Failure of any single AI company, cloud vendor, server, or platform must not directly halt the company.

### 4. Progressive Disclosure

The system is internally complex. The user interface hides that complexity. Users see what their company needs next — not agent parameters, token counts, or tool schemas.

### 5. Verifiable Security

Security claims are proven through public threat models, adversarial tests, and reproducible chaos experiments — not marketing adjectives.

## What Success Looks Like

A stranger can:

1. Turn their skills, constraints, and interests into a testable business direction
2. Define a customer, offer, price, and validation experiment
3. Use an AI crew to create a website, proposal, outreach assets, and delivery plan
4. Move a real prospect through onboarding, delivery, invoicing, and feedback
5. See daily priorities, business metrics, risks, and pending approvals in one place
6. Understand when legal, tax, or financial work needs a qualified professional
7. Approve high-risk actions through clear explanations and bounded authority
8. Survive model or plugin failure and export company data and recovery material without official servers

The defining demo target:

> **Kill the model, the server and the plugin. The company keeps running.**

## What We Are Not

- Not a global AI lawyer or automated tax filing system (in early versions)
- Not a blockchain database for personal data
- Not a multi-agent chat room
- Not a substitute for the founder's judgment or licensed professional advice
- Not dependent on a single model, cloud, or official server
- Not "absolutely secure" — we pursue verifiable, local-first, server-blind security

## Target Users (v1)

- People exploring their first viable one-person business
- Freelancers and digital service providers
- Independent consultants and creators
- Micro-SaaS founders
- Small businesses adopting an AI-assisted operating model

Initial jurisdiction focus: **Singapore** one-person digital service companies. Global expansion via versioned Jurisdiction Packs.

## Open Source Philosophy

Core local Sovereign Runtime capabilities are fully usable without payment. Commercial services (encrypted sync, verified jurisdiction packs, professional networks, managed recovery nodes) must not compromise the security or sovereignty of the free core.

License: **Apache 2.0**. See [LICENSE](LICENSE) and [TRADEMARK.md](TRADEMARK.md).

## Further Reading

| Document | Description |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture and trust boundaries |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threat model v0.1 |
| [PRIVACY_MODEL.md](PRIVACY_MODEL.md) | Data classification and privacy design |
| [ROADMAP.md](ROADMAP.md) | Development stages and milestones |
| [docs/INDEX.md](docs/INDEX.md) | Full documentation map |
| [docs/zh/](docs/zh/) | Complete Chinese design specifications |
