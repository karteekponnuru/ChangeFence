# ChangeFence

**AI security from change to runtime.**

> **Know what changed. Control what it enables.**

[![CI](https://github.com/karteekponnuru/ChangeFence/actions/workflows/ci.yml/badge.svg)](https://github.com/karteekponnuru/ChangeFence/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-555.svg)](LICENSE)

ChangeFence is an open-source AI-agent security suite built around one shared security model: **capabilities, causal origin, invariants, evidence, review, and runtime decisions**.

It connects the security lifecycle:

```text
change
  ↓
Impact
  ↓
Probe
  ↓
Policy
  ↓
Runtime ── REVIEW ── Approval Lease
  ↓
Ledger
```

**Live engine-backed demo:** `https://karteekponnuru.github.io/ChangeFence/`

## The suite

| Module | Question | Current capability |
|---|---|---|
| **Impact** | What security changed? | Capability delta, invariant impact, semantic LLM analysis, PR decision |
| **Probe** | How should the new risk be tested? | Local Ollama hypotheses + change-directed Promptfoo export |
| **Policy** | What control should mitigate it? | Reviewable control plans derived from proven Impact findings |
| **Runtime** | Should this action execute? | Deterministic `ALLOW`, `REVIEW`, `BLOCK` + signed approval leases |
| **Ledger** | What evidence do we retain? | Hash-chained tamper-evident JSONL evidence |

ChangeFence does **not** try to replace cloud-native IAM, cloud agent gateways, generic eval frameworks, or observability systems. It provides the security intelligence and evidence that connects those layers.

---

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

### Run Impact

```bash
changefence impact \
  examples/procurement-base.yaml \
  examples/procurement-candidate.yaml
```

---

## Evidence contract

ChangeFence separates facts from AI-assisted inference.

### `PROVEN`
Derived deterministically from declared architecture and reachability.

### `HYPOTHESIZED`
Proposed by the semantic LLM layer from repository/API/tool evidence. Requires review or runtime verification.

### `VERIFIED`
Reserved for evidence returned by an external execution/evaluation system.

The LLM never upgrades its own inference to `PROVEN` or `VERIFIED`.

---

## Semantic LLM layer

Real repositories rarely use perfect labels such as `payment.execute`. They contain names like:

```text
process_payment
settle_invoice
POST /payments/{id}/execute
finance_mcp
```

The optional local LLM layer translates those implementation details into reviewable capability proposals. OpenAPI/Swagger and MCP-style descriptors can be supplied as grounding context.

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

---

## Probe: change-directed security testing

Probe uses the consequence found by Impact as the target for local LLM hypothesis generation.

```text
PR change
   -> capability delta
   -> affected invariant / semantic risk
   -> targeted hypotheses
   -> Promptfoo / external eval tool
   -> runtime evidence
```

The model proposes. Deterministic analysis and external execution provide evidence.

```bash
changefence hypothesize \
  examples/procurement-base.yaml \
  examples/procurement-candidate.yaml \
  --model gemma3
```

---

## Policy: turn findings into reviewable controls

```bash
changefence policy \
  examples/procurement-base.yaml \
  examples/procurement-candidate.yaml
```

A proven violation can generate a reviewable plan such as:

```text
Intent: Prevent procurement from causing payment.execute.
Triggered by: FIN-001

Options:
- remove or narrow the authority edge
- require explicit human approval
- add a runtime deny rule
```

Policy recommendations are never silently deployed.

---

# Runtime: ALLOW, REVIEW, BLOCK

Runtime is a small pre-action decision hook for custom/local agents.

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

## Configure human review

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

A review can never override a hard security invariant.

---

# Runtime approval leases

A configured `REVIEW` can be satisfied with a **signed, short-lived, scoped approval lease** after a trusted host authenticates the reviewer.

The lease is bound to:

- the review-rule ID
- authenticated reviewer identity and group
- causal origin
- optional executor
- exact capability
- evidence level
- exact modeled authority-path hash
- issue/expiry time
- maximum uses
- optional PR/ticket/request context

## 1. Configure the signing key

Use a secret manager in production. The key must be at least 32 bytes.

```bash
export CHANGEFENCE_APPROVAL_SECRET='replace-with-a-secret-from-your-secret-manager'
```

The signing key is read from an environment variable so it does not need to appear in shell history.

## 2. Trusted host authenticates the reviewer

ChangeFence does not pretend to authenticate the human itself. A GitHub integration, Slack workflow, internal approval service, or other trusted host must establish the human identity and reviewer group first.

Anyone with access to `CHANGEFENCE_APPROVAL_SECRET` is a trusted issuer.

## 3. Issue the lease

```bash
changefence approve \
  examples/procurement-review.yaml \
  procurement \
  supplier.bank_account.write \
  --approved-by alice@example.com \
  --approver-group procurement-security \
  --context '{"pr":284,"ticket":"SEC-91"}' \
  --out approval.json \
  --ledger security-evidence.jsonl
```

## 4. Verify without spending it

```bash
changefence approval-verify \
  examples/procurement-review.yaml \
  procurement \
  supplier.bank_account.write \
  approval.json
```

## 5. Consume at runtime

```bash
changefence runtime \
  examples/procurement-review.yaml \
  procurement \
  supplier.bank_account.write \
  --lease approval.json \
  --usage-store .changefence/approval-usage.json \
  --ledger security-evidence.jsonl
```

A valid lease changes the result to:

```text
Decision: ALLOW
Authorization: APPROVAL_LEASE
Approved by: alice@example.com
Remaining uses: 0
```

### Replay protection

The usage store is signed and updated under an atomic lock/recheck. Two concurrent callers racing a one-use lease cannot both consume it. Tampering with the usage store causes the lease to fail closed.

### Topology binding

The lease includes a hash of the exact authority path that was reviewed. If the agent topology changes before execution, the lease no longer matches and Runtime returns to `REVIEW`.

### What cannot be approved around

A lease cannot bypass:

- an explicit `BLOCK` invariant
- unknown/unmodeled authority
- a different origin, executor, capability, reviewer group, or rule
- expiration or exhausted uses
- an invalid signature
- a changed authority path

Detailed design: [`docs/approval-leases.md`](docs/approval-leases.md)

---

## Ledger: retain the evidence

Append an event:

```bash
changefence ledger-append evidence.jsonl impact \
  '{"decision":"BLOCK","capability":"payment.execute"}'
```

Verify the chain:

```bash
changefence ledger-verify evidence.jsonl
```

Approval issuance and successful lease consumption can also be written to the Ledger. Each record includes the previous record hash, so changing earlier evidence breaks verification.

---

## Real demo results, not hard-coded screenshots

The GitHub Pages demo loads JSON under `docs/demo-data/`.

Those artifacts are generated by the real engines:

```bash
python scripts/generate_demo_results.py
```

CI runs:

```bash
python scripts/generate_demo_results.py --check
```

and fails if the published demo data differs from current engine output.

Reproducible examples include:

- Procurement delegation → `payment.execute` → **BLOCK**
- Support delegation → `customer.pii.export` → **BLOCK**
- Coding agent receives deploy tool → `production.deploy` → **BLOCK**
- Prompt-only change with unchanged authority → **PASS**
- Sensitive supplier-bank update → **REVIEW**
- Signed one-use approval lease consumed → **ALLOW**

The public Runtime tab lets you switch from the actual pre-approval `REVIEW` result to the engine-generated approved execution result.

---

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

---

## Core commands

```bash
# Change-to-consequence analysis
changefence impact BASELINE CANDIDATE

# Runtime decision
changefence runtime SPEC ORIGIN CAPABILITY [--executor AGENT]

# Issue a signed review lease
changefence approve SPEC ORIGIN CAPABILITY \
  --approved-by USER \
  --approver-group GROUP \
  --out approval.json

# Validate without consuming
changefence approval-verify SPEC ORIGIN CAPABILITY approval.json

# Consume a lease during Runtime authorization
changefence runtime SPEC ORIGIN CAPABILITY \
  --lease approval.json \
  --usage-store .changefence/approval-usage.json

# Reviewable policy plan
changefence policy BASELINE CANDIDATE

# Local LLM security hypotheses
changefence hypothesize BASELINE CANDIDATE --model gemma3

# Evidence ledger
changefence ledger-append LEDGER EVENT_TYPE JSON_PAYLOAD
changefence ledger-verify LEDGER
```

Lower-level primitives such as `compare`, `behavior-diff`, and `report` remain available for compatibility.

---

## Repository structure

```text
changefence/
  engine.py          deterministic authority analysis
  impact.py          change-to-consequence workflow
  semantic.py        local-LLM semantic compiler
  descriptors.py     OpenAPI / MCP grounding
  hypotheses.py      Probe hypothesis engine
  policy.py          reviewable control recommendations
  runtime.py         ALLOW / REVIEW / BLOCK + lease authorization
  approvals.py       signed scoped approval leases + replay protection
  ledger.py          tamper-evident evidence chain
  cli.py             command-line suite

docs/
  index.html         interactive product demo
  app.css / app.js   public demo UI
  demo-data/         engine-generated result artifacts
  approval-leases.md approval trust model and integration guide
examples/            reproducible security scenarios
tests/               deterministic, LLM-boundary, runtime, approval, policy and ledger tests
scripts/             demo artifact generator
action.yml           reusable GitHub PR/release gate
```

## Current scope and limits

ChangeFence only makes deterministic authority claims about capabilities and relationships it can model. Dynamic runtime-only authority, undocumented side effects, arbitrary credential discovery, and environment-specific behavior require runtime or external evidence.

`Runtime` is currently a decision/authorization hook for custom/local systems, not a universal network gateway. Approval identity is authenticated by the integrating host, not by ChangeFence itself. `Policy` produces reviewable plans rather than silently changing production controls. `Probe` uses local LLMs for hypotheses rather than verdicts.

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
