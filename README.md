# ChangeFence

**AI security from change to runtime.**

> **Know what changed. Control what it enables.**

[![CI](https://github.com/karteekponnuru/ChangeFence/actions/workflows/ci.yml/badge.svg)](https://github.com/karteekponnuru/ChangeFence/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-555.svg)](LICENSE)

ChangeFence is an open-source AI-agent security suite built around one shared security model: **capabilities, causal origin, invariants, evidence, and decisions**.

It starts with the question that created the project:

> **What new security authority did this change create, and why?**

and carries that result into targeted testing, control recommendations, runtime decisions, and evidence retention.

**Live engine-backed demo:** `https://karteekponnuru.github.io/ChangeFence/`

## The suite

| Module | Question | Current capability |
|---|---|---|
| **Impact** | What security changed? | Structural capability delta, invariant impact, semantic LLM analysis, PR decision |
| **Probe** | How should the new risk be tested? | Local Ollama hypotheses + change-directed Promptfoo export |
| **Policy** | What control should mitigate it? | Reviewable control plans derived from proven Impact findings |
| **Runtime** | Should this action execute? | Deterministic `ALLOW`, `REVIEW`, `BLOCK` hook for custom/local agents |
| **Ledger** | What evidence do we retain? | Hash-chained tamper-evident JSONL evidence |

ChangeFence does **not** try to replace cloud-native IAM, AWS AgentCore Policy, Google Agent Gateway, Promptfoo, LangSmith, or existing observability systems. It can feed or complement those systems while retaining one security story across the lifecycle.

## Impact: your code diff is not your agent diff

A PR may contain one small-looking change:

```diff
 procurement:
   tools: [supplier]
+  delegates_to: [finance]
```

ChangeFence computes the consequence:

```text
CHANGEFENCE IMPACT

Decision: BLOCK

PROVEN CAPABILITY DELTA

+ procurement -> invoice.read
+ procurement -> payment.execute   CRITICAL

Causal path
procurement
  -> delegate:finance
  -> finance
  -> tool:payments
  -> cap:payment.execute

Violated invariant
FIN-001: Procurement must never gain authority to execute payments.
```

The developer never directly granted `payment.execute` to Procurement. The graph reveals the transitive consequence.

## Evidence contract

ChangeFence separates facts from AI-assisted inference.

### `PROVEN`
Derived deterministically from declared architecture and reachability.

### `HYPOTHESIZED`
Proposed by the semantic LLM layer from concrete repository/API/tool evidence. Requires review or runtime verification.

### `VERIFIED`
Reserved for evidence returned by an external execution/evaluation system.

The LLM never upgrades its own inference to `PROVEN` or `VERIFIED`.

## Semantic LLM layer

Real repositories do not contain perfect labels such as `payment.execute`. They contain names like:

```text
process_payment
settle_invoice
POST /payments/{id}/execute
finance_mcp
```

The optional local LLM layer translates messy implementation details into reviewable capability proposals. OpenAPI/Swagger and MCP-style descriptors can be supplied as grounding context.

```bash
changefence impact \
  examples/procurement-base.yaml \
  examples/procurement-candidate.yaml \
  --llm \
  --diff examples/procurement-release.patch \
  --descriptor examples/finance-openapi.json \
  --descriptor examples/finance-mcp.json \
  --promptfoo-out changefence-tests.yaml
```

Unknown tools, malformed capabilities, invented agents, and generated tests outside the actual change impact are discarded.

## Probe: change-directed security testing

Probe uses the security consequence found by Impact as the target for local LLM hypothesis generation.

```text
PR change
   -> capability delta
   -> affected invariant / semantic risk
   -> targeted hypotheses
   -> Promptfoo / external eval tool
   -> runtime evidence
```

ChangeFence does not pretend that hypothesis generation is a security verdict. The model proposes; deterministic analysis and external execution provide evidence.

## Policy: turn findings into reviewable controls

```bash
changefence policy \
  examples/procurement-base.yaml \
  examples/procurement-candidate.yaml
```

A proven violation can produce a plan such as:

```text
Intent: Prevent procurement from causing payment.execute.
Triggered by: FIN-001
Options:
- remove or narrow the authority edge
- require explicit human approval
- add a runtime deny rule
```

Policy recommendations are never silently deployed.

## Runtime: ALLOW, REVIEW, or BLOCK

Runtime is a small pre-action decision hook for custom/local agents. Cloud-hosted systems should normally use their native enforcement mechanisms.

Decision precedence:

```text
Explicit invariant violation   -> BLOCK
Unknown/unmodeled authority    -> REVIEW
Configured review requirement  -> REVIEW
Known reachable authority      -> ALLOW
```

Example:

```bash
changefence runtime \
  examples/procurement-review.yaml \
  procurement \
  supplier.bank_account.write
```

Result:

```text
Decision: REVIEW
Reviewer: procurement-security
Approval: 1 use, expires in 15 minutes
```

### Configure human review

```yaml
reviews:
  - id: REV-001
    match:
      origin: procurement
      capability: supplier.bank_account.write
      severity_at_least: high
    require:
      approver: procurement-security
      expires_minutes: 15
      max_uses: 1
      reason: Human approval required for sensitive supplier-bank changes.
```

The host system is responsible for authenticating the human reviewer. ChangeFence defines **when review is required, who should approve, and the intended approval scope**. A review can never override a hard security invariant.

## Ledger: retain the evidence

Append a security event:

```bash
changefence ledger-append evidence.jsonl impact \
  '{"decision":"BLOCK","capability":"payment.execute"}'
```

Verify the chain:

```bash
changefence ledger-verify evidence.jsonl
```

Each record includes the previous record hash. Tampering with an earlier event breaks verification.

## Real demo results, not hard-coded screenshots

The GitHub Pages demo loads result JSON under `docs/demo-data/`.

Those artifacts are generated by:

```bash
python scripts/generate_demo_results.py
```

CI runs:

```bash
python scripts/generate_demo_results.py --check
```

and fails if the published demo data differs from what the current engine generates.

Current reproducible scenarios include:

- Procurement delegation → `payment.execute` → **BLOCK**
- Support delegation → `customer.pii.export` → **BLOCK**
- Coding agent receives deploy tool → `production.deploy` → **BLOCK**
- Prompt-only change with unchanged authority → **PASS**
- Sensitive supplier-bank update review rule → **REVIEW**

All scenario inputs are committed under `examples/`.

## GitHub Action

```yaml
- name: ChangeFence Impact
  uses: karteekponnuru/ChangeFence@main
  with:
    baseline: security/agent-baseline.yaml
    candidate: security/agent-candidate.yaml
    fail-on: high
```

The Action blocks only on a newly introduced deterministic authority path that violates a configured invariant at or above the selected severity. LLM-assisted findings are surfaced for review instead of autonomously blocking the build.

## Core commands

```bash
# Change-to-consequence analysis
changefence impact BASELINE CANDIDATE

# Runtime decision
changefence runtime SPEC ORIGIN CAPABILITY [--executor AGENT]

# Reviewable policy plan
changefence policy BASELINE CANDIDATE

# Local LLM security hypotheses
changefence hypothesize BASELINE CANDIDATE --model gemma3

# Evidence ledger
changefence ledger-append LEDGER EVENT_TYPE JSON_PAYLOAD
changefence ledger-verify LEDGER
```

Lower-level primitives such as `compare`, `behavior-diff`, and `report` remain available for compatibility.

## Repository structure

```text
changefence/
  engine.py          deterministic authority analysis
  impact.py          change-to-consequence workflow
  semantic.py        local-LLM semantic compiler
  descriptors.py     OpenAPI / MCP grounding
  hypotheses.py      Probe hypothesis engine
  policy.py          reviewable control recommendations
  runtime.py         ALLOW / REVIEW / BLOCK hook
  ledger.py          tamper-evident evidence chain
  cli.py             command-line suite

docs/
  index.html         interactive product demo
  app.css / app.js   public demo UI
  demo-data/         engine-generated result artifacts
examples/            reproducible security scenarios
tests/               deterministic, LLM-boundary, runtime, policy and ledger tests
scripts/             demo artifact generator
action.yml           reusable GitHub PR/release gate
```

## Current scope and limits

ChangeFence only makes deterministic authority claims about capabilities and relationships it can model. Dynamic runtime-only authority, undocumented side effects, arbitrary credential discovery, and environment-specific behavior require runtime or external evidence.

`Runtime` is currently a decision hook for custom/local systems, not a universal network gateway. `Policy` produces reviewable plans rather than silently changing production controls. `Probe` uses local LLMs for hypotheses rather than verdicts.

These boundaries are intentional.

## Development

Requires Python 3.10+.

```bash
python -m pip install -e ".[dev]"
pytest
python scripts/generate_demo_results.py --check
```

## Author

Created by **Karteek Ponnuru** as an open-source AI-agent security project.

## License

MIT
