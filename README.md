# ChangeFence

**Security change control for AI agents.**

> **Your code diff is not your agent diff.**

A small change to an AI agent can create a large security change. Adding a tool, changing a prompt, switching a model, or allowing one agent to delegate to another can create authority that is not obvious from the code review itself.

ChangeFence compares a known baseline with a proposed release and answers two questions:

1. **What security-relevant authority became newly reachable?**
2. **Did repeated adversarial tests become worse in the candidate release?**

The result is a deterministic security gate that can block a release when a non-negotiable security invariant is violated.

## The problem in one example

A Procurement Agent can update supplier records. A Finance Agent can execute payments. Neither permission is unusual.

A release adds this feature:

```text
Procurement Agent → may delegate to → Finance Agent
```

Now Procurement can indirectly reach `payment.execute` through Finance. Every individual permission is valid, but the combined authority violates the business rule:

> Procurement must never gain authority to execute a payment.

ChangeFence detects the new path and blocks the release.

```text
CHANGEFENCE
Baseline:  acme-procurement-baseline
Candidate: acme-procurement-candidate

Security gate: FAIL

[CRITICAL] FIN-001 — Procurement must never gain authority to execute payments.
New authority: procurement -> payment.execute
Path: procurement -> delegate:finance -> finance -> tool:payments -> cap:payment.execute
```

## Explore it without being technical

The `docs/` folder contains the ChangeFence browser playground. It explains the problem and runs the core demo with one click. The repository also includes a GitHub Pages deployment workflow so the playground can be hosted publicly.

## What ChangeFence analyzes

### Authority security diff

ChangeFence understands:

- agents
- tools
- security-relevant capabilities
- agent-to-agent delegation
- prompt identifiers
- model changes
- security invariants
- capability severity

It computes transitive authority, compares the baseline and candidate, and explains the shortest newly introduced path to a forbidden capability.

### Behavioral security diff

ChangeFence can also compare repeated adversarial test results produced by any agent framework. The framework only needs to provide scenario IDs and pass/fail outcomes. This keeps ChangeFence model- and framework-independent.

Example:

```text
INDIRECT-PROMPT-INJECTION     100% → 30%   REGRESSION
SENSITIVE-DATA-EXFILTRATION   90%  → 90%   UNCHANGED
TOOL-AUTHORITY-ESCALATION     100% → 40%   REGRESSION
```

## Run it

Requires Python 3.10+.

```bash
python -m pip install -e .
```

Run the authority diff:

```bash
changefence compare \
  examples/procurement-base.yaml \
  examples/procurement-candidate.yaml
```

A security regression exits with status code `1`, so CI/CD systems can block the release.

Run the behavioral diff:

```bash
changefence behavior-diff \
  examples/behavior-base.json \
  examples/behavior-candidate.json
```

Generate a shareable HTML security report:

```bash
changefence report \
  examples/procurement-base.yaml \
  examples/procurement-candidate.yaml \
  --behavior-base examples/behavior-base.json \
  --behavior-candidate examples/behavior-candidate.json \
  --out changefence-report.html
```

## Use ChangeFence in a GitHub workflow

This repository is also a composite GitHub Action. In another repository:

```yaml
- name: ChangeFence agent security gate
  uses: karteekponnuru/ChangeFence@main
  with:
    baseline: security/agent-baseline.yaml
    candidate: security/agent-candidate.yaml
    fail-on: high
```

If the candidate introduces a new invariant violation at or above the configured severity, the workflow fails.

## Agent system specification

ChangeFence uses a small YAML file because it is easy for code and CI systems to read. You do **not** need YAML to understand or explore the product; it is the developer integration format underneath the browser experience.

```yaml
system: acme-procurement

agents:
  procurement:
    tools: [supplier]
    delegates_to: [finance]
  finance:
    tools: [payments]

tools:
  supplier:
    capabilities:
      - name: supplier.bank_account.write
        severity: high
  payments:
    capabilities:
      - name: payment.execute
        severity: critical

invariants:
  - id: FIN-001
    severity: critical
    description: Procurement must never gain authority to execute payments.
    forbid_reachability:
      from: procurement
      to: payment.execute
```

## Design principle

LLMs may be useful for generating candidate attack scenarios, but **an LLM should not be allowed to invent whether an authority path exists**. ChangeFence keeps the core capability and invariant analysis deterministic and explainable.

## Repository map

```text
changefence/          Python analysis engine and CLI
docs/                 Public browser playground and plain-English concepts
examples/             Safe and unsafe agent releases + behavioral test data
tests/                Automated regression tests
action.yml            Reusable GitHub security gate
.github/workflows/    CI and GitHub Pages deployment
```

## Scope

ChangeFence is a security change-control layer, not a replacement for IAM, runtime authorization, model safety filters, monitoring, or human approvals. It is designed to catch **release-to-release security regressions** that those controls may not make obvious during review.

## Author

Created by **Karteek Ponnuru** as an open-source security project for autonomous AI systems.

## License

MIT.
