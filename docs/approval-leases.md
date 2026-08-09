# ChangeFence Runtime approval leases

Approval leases turn a configured `REVIEW` decision into a short-lived, scoped runtime authorization without weakening hard security invariants.

## Trust model

ChangeFence does **not** authenticate the human reviewer itself. A trusted host such as an internal approval service, GitHub integration, Slack workflow, or cloud workflow must authenticate the person and determine their group/role first.

The trusted host then calls ChangeFence with:

- the authenticated human identity (`approved_by`)
- the authenticated reviewer group (`approver_group`)
- the action being reviewed
- a signing secret available only to trusted issuers/runtime validators

Anyone who can access `CHANGEFENCE_APPROVAL_SECRET` is a trusted lease issuer. Store that secret in a proper secret manager in production; do not commit it or pass it on the command line.

## Configure review

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

Runtime first returns:

```text
Decision: REVIEW
Reviewer: procurement-security
Approval: 1 use, expires in 15 minutes
```

## Issue a lease

Set a signing secret of at least 32 bytes:

```bash
export CHANGEFENCE_APPROVAL_SECRET='replace-with-a-secret-from-your-secret-manager'
```

After the host has authenticated the reviewer:

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

The resulting lease is HMAC-SHA256 signed and contains:

- unique lease ID
- configured review-rule ID
- authenticated reviewer identity and group
- causal origin
- optional executor
- exact capability
- evidence level
- hash of the exact modeled authority path
- issue and expiration timestamps
- maximum uses
- optional PR/ticket/request context

## Verify without consuming

```bash
changefence approval-verify \
  examples/procurement-review.yaml \
  procurement \
  supplier.bank_account.write \
  approval.json
```

Verification fails closed if the lease is expired, tampered with, scoped to another action, bound to a different authority path, exceeds the review rule's lifetime/use limit, or references a review rule that no longer exists.

## Consume at runtime

```bash
changefence runtime \
  examples/procurement-review.yaml \
  procurement \
  supplier.bank_account.write \
  --lease approval.json \
  --usage-store .changefence/approval-usage.json \
  --ledger security-evidence.jsonl
```

A valid lease changes the runtime result from `REVIEW` to:

```text
Decision: ALLOW
Authorization: APPROVAL_LEASE
Approved by: alice@example.com
Remaining uses: 0
```

The usage store is itself signed and is updated under an atomic lock/recheck. This prevents two concurrent callers from both spending the same one-use lease. Tampering with the usage store causes ChangeFence to refuse the lease.

## What a lease cannot override

### Hard invariant

If an invariant says:

```text
Procurement must never cause payment.execute
```

then Runtime returns `BLOCK` before lease validation. No approval lease can bypass it.

### Unknown/unmodeled authority

A default review caused by an unknown capability such as `root.shell` cannot be converted to `ALLOW` with an approval lease. The model must first be updated so ChangeFence can reason about the authority explicitly.

## Decision order

```text
Explicit invariant violation
        -> BLOCK

Unknown/unmodeled authority
        -> REVIEW (not lease-approvable)

Configured review rule
        -> REVIEW
        -> authenticated host issues signed lease
        -> exact scoped lease is consumed
        -> ALLOW

Known reachable, unrestricted authority
        -> ALLOW
```

## Ledger evidence

With `--ledger`, ChangeFence records lease issuance and successful consumption as hash-chained evidence events. The lease signature itself is not written to the issuance event; the security-relevant claims and lease ID are retained.

## Production integration

The current implementation is a local/custom-agent security primitive. A production integration should connect the trusted-issuer step to the organization's identity and approval system, for example:

```text
Runtime REVIEW
    ↓
GitHub / Slack / internal approval service
    ↓ authenticate human + group
ChangeFence approve
    ↓ signed scoped lease
Runtime
    ↓ validate + consume
ALLOW once / until configured use limit
    ↓
Ledger evidence
```

Cloud-hosted agents can use the same ChangeFence review decision and evidence model while delegating the final enforcement step to their native runtime policy stack.
