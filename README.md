<div align="center">

# 🛡️ CHANGEFENCE

### **Your code diff is not your agent diff.**

Security change control for AI agents.

[![Tests](https://github.com/karteekponnuru/ChangeFence/actions/workflows/ci.yml/badge.svg)](https://github.com/karteekponnuru/ChangeFence/actions/workflows/ci.yml)
[![Playground](https://img.shields.io/badge/⚡_Interactive_Playground-54E1FF?style=for-the-badge&labelColor=07111f)](https://karteekponnuru.github.io/ChangeFence/)
[![License: MIT](https://img.shields.io/badge/License-MIT-9CFF57.svg?style=for-the-badge&labelColor=07111f)](LICENSE)

**A tiny agent change can create a massive security change. ChangeFence finds the consequence before it ships.**

[🎮 Break the demo](https://karteekponnuru.github.io/ChangeFence/) · [⚙️ How it works](#-how-it-works) · [🧪 Run locally](#-try-it-yourself)

</div>

---

## 🎮 Can you break this agent?

Imagine this perfectly reasonable AI setup:

```text
🤖 Procurement Agent            🧠 Finance Agent
   │                                 │
   ├── supplier.read                 ├── invoice.read
   └── supplier.write                └── payment.execute
```

Neither agent has an obviously dangerous permission problem.

Now a developer adds one small feature:

```diff
+ Procurement Agent → may delegate to → Finance Agent
```

Suddenly this becomes possible:

```text
✉️ Malicious supplier email
        ↓
🤖 Procurement Agent
        ↓ delegates
🧠 Finance Agent
        ↓
💸 payment.execute
```

Every individual permission is legitimate.

The **combined authority is not**.

ChangeFence detects that new security path and blocks the release.

> **This is the core idea:** agent security can change even when traditional code review and individual permissions look fine.

### 👉 [Try the interactive security lab](https://karteekponnuru.github.io/ChangeFence/)

---

## 🧠 What ChangeFence actually asks

When an AI agent changes, ChangeFence compares the trusted baseline with the proposed release and asks:

| Question | Why it matters |
|---|---|
| 🧬 What changed? | Model, prompt, tool or agent-to-agent delegation |
| 🔓 What became newly reachable? | New indirect authority can appear through composition |
| 🚨 Did a security invariant break? | Critical rules become deterministic release gates |
| 🧪 Did adversarial behavior get worse? | Candidate releases can be compared against repeated attack tests |

---

## 🕸️ How it works

```mermaid
flowchart LR
    A[Trusted Agent Release] --> C[ChangeFence]
    B[Candidate Agent Release] --> C
    C --> D{What changed?}
    D --> E[Prompt]
    D --> F[Model]
    D --> G[Tools]
    D --> H[Delegation]
    E --> I[Capability Graph]
    F --> I
    G --> I
    H --> I
    I --> J[Security Invariants]
    J --> K{New unsafe path?}
    K -->|No| L[✅ PASS]
    K -->|Yes| M[❌ BLOCK RELEASE]
```

ChangeFence's authority engine is deterministic. An LLM may eventually help **suggest attack hypotheses**, but the LLM does not get to invent whether a security path actually exists.

---

## 💥 What a finding looks like

```text
CHANGEFENCE

Baseline:  acme-procurement-baseline
Candidate: acme-procurement-candidate

Security gate: FAIL 🔴

[CRITICAL] FIN-001
Procurement must never gain authority to execute payments.

New authority:
procurement → finance → payment.execute

Path:
procurement
→ delegate:finance
→ finance
→ tool:payments
→ payment.execute

❌ BLOCK RELEASE
```

---

## 🧪 Behavioral security diff

ChangeFence can also compare repeated adversarial tests between releases.

```text
ATTACK SCENARIO                     BASELINE     CANDIDATE
────────────────────────────────────────────────────────
Indirect prompt injection            100%          30%  🔴
Sensitive-data exfiltration            90%          90%  🟢
Tool-authority escalation             100%          40%  🔴
```

That turns a vague question like:

> Did the new agent become less safe?

into something measurable.

---

## 🚦 Use it as a release gate

ChangeFence is also a reusable GitHub Action.

```yaml
- name: ChangeFence agent security gate
  uses: karteekponnuru/ChangeFence@main
  with:
    baseline: security/agent-baseline.yaml
    candidate: security/agent-candidate.yaml
    fail-on: high
```

A newly introduced high or critical security invariant violation makes the workflow fail.

```text
Developer changes agent
        ↓
      GitHub
        ↓
   ChangeFence
     ↙     ↘
  ✅ PASS   ❌ BLOCK
```

---

## 🧪 Try it yourself

Requires Python 3.10+.

```bash
python -m pip install -e .
```

### 1. Break the procurement agent

```bash
changefence compare \
  examples/procurement-base.yaml \
  examples/procurement-candidate.yaml
```

Expected result: **FAIL** because the candidate introduces transitive payment authority.

### 2. Compare against a safe change

```bash
changefence compare \
  examples/procurement-base.yaml \
  examples/procurement-safe-candidate.yaml
```

Expected result: **PASS**.

### 3. Run behavioral regression analysis

```bash
changefence behavior-diff \
  examples/behavior-base.json \
  examples/behavior-candidate.json
```

### 4. Generate a shareable report

```bash
changefence report \
  examples/procurement-base.yaml \
  examples/procurement-candidate.yaml \
  --behavior-base examples/behavior-base.json \
  --behavior-candidate examples/behavior-candidate.json \
  --out changefence-report.html
```

---

## 🧩 What is an agent spec?

ChangeFence needs a machine-readable description of an AI system. Today that uses YAML.

You do **not** need to understand YAML to explore ChangeFence. Think of it as a form describing:

```text
Agent
├── Which model does it use?
├── Which tools can it call?
├── Which other agents can it delegate to?
└── Which security rules must never be violated?
```

Example:

```yaml
agents:
  procurement:
    tools: [supplier]
    delegates_to: [finance]

  finance:
    tools: [payments]

invariants:
  - id: FIN-001
    description: Procurement must never execute payments.
    forbid_reachability:
      from: procurement
      to: payment.execute
```

---

## 🔬 Product thesis

Traditional software review answers:

> **What code changed?**

ChangeFence is built around a different question:

> **What security behavior became possible because of that change?**

As AI systems gain tools, memory, APIs, MCP servers and agent-to-agent delegation, those two questions increasingly diverge.

---

## 🗺️ Project map

```text
ChangeFence/
│
├── 🧠 changefence/          deterministic security engine
├── 🎮 docs/                 interactive browser playground
├── 🧪 examples/             safe + vulnerable agent releases
├── ✅ tests/                automated regression tests
├── 🛡️ action.yml           reusable GitHub security gate
└── ⚙️ .github/workflows/    CI + playground deployment
```

---

## 🧱 What ChangeFence is not

ChangeFence does **not** replace IAM, runtime authorization, model safety filters, monitoring or human approvals.

It focuses on one specific gap:

> **security regressions introduced when an AI agent changes.**

---

## 👋 Built by

**Karteek Ponnuru**

Exploring the intersection of **AI agents × security × authorization × governance**.

If this problem is interesting to you, break the demo, open an issue, challenge the threat model, or contribute another vulnerable agent scenario.

<div align="center">

### [⚡ Launch ChangeFence Playground](https://karteekponnuru.github.io/ChangeFence/)

MIT License · Open source

</div>
