# ChangeFence

**AI security from change to runtime.**

> **Your code diff is not your agent diff.**

[![CI](https://github.com/karteekponnuru/ChangeFence/actions/workflows/ci.yml/badge.svg)](https://github.com/karteekponnuru/ChangeFence/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-555.svg)](LICENSE)

ChangeFence answers a practical security question for AI-agent systems:

> **What new authority did this change create, and does company security policy allow it?**

**Live engine-backed demo:** https://karteekponnuru.github.io/ChangeFence/

## The use case

A developer wants Procurement to ask Finance for help with invoice questions, so they add:

```diff
 procurement:
   tools: [supplier]
+  delegates_to: [finance]
```

Finance already has `payment.execute`.

The developer never wrote “give Procurement payment authority,” but the system now contains this path:

```text
procurement
  -> finance
  -> payments
  -> payment.execute
```

ChangeFence detects that consequence and evaluates it against a **separate security-owned policy**.

```yaml
policy:
  name: ACME Agent Security Policy
  version: "3.2"
  owner: Enterprise Security

invariants:
  - id: FIN-001
    severity: critical
    description: Procurement must never gain authority to execute payments.
    forbid_reachability:
      from: procurement
      to: payment.execute
```

Result:

```text
Decision: BLOCK
Policy: ACME Agent Security Policy v3.2
Rule: FIN-001

New authority:
procurement -> finance -> payment.execute
```

## Security ground truth is separate from agent code

This is the recommended enterprise setup:

```text
agents/
  procurement.yaml          # developer-owned

security/
  company-policy.yaml       # security-owned
```

Run ChangeFence with both:

```bash
changefence impact \
  examples/procurement-agents-base.yaml \
  examples/procurement-agents-candidate.yaml \
  --policy examples/acme-security-policy.yaml
```

When `--policy` is supplied:

- invariants come from the external policy file;
- human-review rules come from the external policy file;
- rules embedded in developer-controlled agent YAML are ignored;
- decisions include policy name, version, owner and SHA-256 digest.

That means a developer cannot neutralize a security rule in the same PR as the risky agent change.

The external policy example is [`examples/acme-security-policy.yaml`](examples/acme-security-policy.yaml).

## Runtime

The same security policy can be used while an agent is live.

```bash
changefence runtime \
  examples/procurement-agents-base.yaml \
  procurement \
  supplier.bank_account.write \
  --policy examples/acme-security-policy.yaml
```

The policy says this high-risk action requires Procurement Security review, so ChangeFence returns:

```text
REVIEW
Reviewer: procurement-security
Approval: 1 use, 15 minutes
```

After a trusted host authenticates the reviewer, ChangeFence can issue a signed, short-lived approval lease.

```bash
export CHANGEFENCE_APPROVAL_SECRET='your-secret-at-least-32-bytes'

changefence approve \
  examples/procurement-agents-base.yaml \
  procurement \
  supplier.bank_account.write \
  --policy examples/acme-security-policy.yaml \
  --approved-by alice@example.com \
  --approver-group procurement-security \
  --out approval.json
```

The runtime can consume that approval once:

```bash
changefence runtime \
  examples/procurement-agents-base.yaml \
  procurement \
  supplier.bank_account.write \
  --policy examples/acme-security-policy.yaml \
  --lease approval.json
```

Hard invariants cannot be overridden by a human approval.

## The suite

| Module | Question |
|---|---|
| **Impact** | What security authority did the change create? |
| **Probe** | How should the new risk be tested? |
| **Policy** | What control should mitigate it? |
| **Runtime** | Should this action execute now? |
| **Ledger** | What evidence do we retain? |

The shared model is **capability + causal origin + policy + evidence + decision**.

## Evidence contract

ChangeFence keeps deterministic facts separate from AI-assisted inference:

- **PROVEN** — derived deterministically from declared architecture and reachability.
- **HYPOTHESIZED** — LLM-assisted interpretation requiring review or runtime verification.
- **VERIFIED** — evidence returned by an external execution/evaluation system.

The LLM can help understand messy prompts, APIs, OpenAPI descriptions and MCP tools. It does **not** get to invent a deterministic security verdict.

## Probe and semantic analysis

```bash
changefence impact \
  examples/procurement-agents-base.yaml \
  examples/procurement-agents-candidate.yaml \
  --policy examples/acme-security-policy.yaml \
  --llm \
  --diff examples/procurement-release.patch \
  --descriptor examples/finance-openapi.json \
  --descriptor examples/finance-mcp.json \
  --promptfoo-out changefence-tests.yaml
```

ChangeFence can use a local Ollama model to normalize messy tool/API descriptions and generate **change-directed** attack hypotheses. These remain `HYPOTHESIZED` until an external harness executes them.

## GitHub Action

```yaml
- name: ChangeFence Impact
  uses: karteekponnuru/ChangeFence@main
  with:
    baseline: agents/baseline.yaml
    candidate: agents/candidate.yaml
    policy: security/company-policy.yaml
    fail-on: high
```

For an enterprise repository, protect `security/company-policy.yaml` with branch protection / CODEOWNERS so the security team controls the ground truth independently from agent developers.

## Ledger

Security-relevant decisions can be retained in a tamper-evident hash-chained JSONL ledger.

```bash
changefence ledger-append evidence.jsonl runtime '{"decision":"BLOCK","rule":"FIN-001"}'
changefence ledger-verify evidence.jsonl
```

## Core commands

```bash
changefence impact BASELINE CANDIDATE --policy POLICY
changefence runtime SPEC ORIGIN CAPABILITY --policy POLICY
changefence approve SPEC ORIGIN CAPABILITY --policy POLICY ...
changefence approval-verify SPEC ORIGIN CAPABILITY LEASE --policy POLICY
changefence policy BASELINE CANDIDATE --policy POLICY
changefence hypothesize BASELINE CANDIDATE --policy POLICY
```

Legacy combined agent+policy YAML files remain supported when `--policy` is omitted.

## Current boundary

ChangeFence is currently an open-source technical MVP. Runtime is a decision hook for custom/local agent systems rather than a universal network gateway. Enterprise integrations should call it before security-sensitive tool execution or adapt its decisions into cloud-native enforcement systems.

It deliberately does not try to replace IAM, cloud agent gateways, generic eval frameworks or observability systems.

## Development

Requires Python 3.10+.

```bash
python -m pip install -e ".[dev]"
pytest
python scripts/generate_demo_results.py --check
```

## Author

Created by **Karteek Ponnuru**.

## License

MIT
