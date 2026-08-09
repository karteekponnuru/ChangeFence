"""Runtime decision hook for custom/local agent execution paths.

This is intentionally small: it is not a replacement for cloud-native gateways.
It gives custom agent systems a deterministic pre-action decision using the same
invariants and authority model as ChangeFence Impact.
"""
from __future__ import annotations

from .engine import SEVERITY_RANK, analyze, index_by_pair
from .models import ReviewRule, SystemSpec
from .spec import policy_authority_dict


class RuntimeDecisionError(ValueError):
    pass


def _capability_severity(spec: SystemSpec, capability: str) -> str | None:
    for tool in spec.tools.values():
        for cap in tool.capabilities:
            if cap.name == capability:
                return cap.severity
    return None


def _review_requirement(rule: ReviewRule | None, *, reason: str) -> dict:
    if rule is None:
        return {
            "rule_id": "DEFAULT_REVIEW",
            "approver": "security",
            "expires_minutes": 15,
            "max_uses": 1,
            "reason": reason,
        }
    return {
        "rule_id": rule.id,
        "approver": rule.approver,
        "expires_minutes": rule.expires_minutes,
        "max_uses": rule.max_uses,
        "reason": rule.reason,
    }


def _decision(spec: SystemSpec, payload: dict) -> dict:
    return {**payload, "policy_authority": policy_authority_dict(spec)}


def _matching_review_rule(
    spec: SystemSpec,
    *,
    origin_agent: str,
    capability: str,
    severity: str,
    evidence: str,
) -> ReviewRule | None:
    matches = []
    for rule in spec.review_rules:
        if rule.origin_agent not in {"*", origin_agent}:
            continue
        if rule.capability not in {"*", capability}:
            continue
        if rule.evidence not in {"*", evidence}:
            continue
        if SEVERITY_RANK[severity] < SEVERITY_RANK[rule.severity_at_least]:
            continue
        matches.append(rule)
    if not matches:
        return None
    matches.sort(
        key=lambda rule: (
            rule.origin_agent != "*",
            rule.capability != "*",
            rule.evidence != "*",
            SEVERITY_RANK[rule.severity_at_least],
            -rule.expires_minutes,
        ),
        reverse=True,
    )
    return matches[0]


def decide_action(
    spec: SystemSpec,
    *,
    origin_agent: str,
    capability: str,
    executor_agent: str | None = None,
) -> dict:
    """Return ALLOW, REVIEW, or BLOCK before a security-relevant action executes.

    Precedence is deliberate:
    1. explicit invariant -> BLOCK
    2. unknown/unmodeled authority -> REVIEW
    3. configured review rule -> REVIEW
    4. modeled reachable authority -> ALLOW
    """
    origin_agent = str(origin_agent).strip()
    capability = str(capability).strip()
    executor_agent = str(executor_agent).strip() if executor_agent else None

    if origin_agent not in spec.agents:
        raise RuntimeDecisionError(f"Unknown origin agent '{origin_agent}'.")
    if executor_agent and executor_agent not in spec.agents:
        raise RuntimeDecisionError(f"Unknown executor agent '{executor_agent}'.")
    if not capability:
        raise RuntimeDecisionError("Capability is required.")

    matching_invariants = [
        inv for inv in spec.invariants
        if inv.source_agent == origin_agent and inv.forbidden_capability == capability
    ]
    if matching_invariants:
        inv = sorted(matching_invariants, key=lambda item: item.id)[0]
        return _decision(spec, {
            "decision": "BLOCK",
            "origin_agent": origin_agent,
            "executor_agent": executor_agent,
            "capability": capability,
            "reason": f"Explicit invariant {inv.id} forbids this causal origin from reaching {capability}.",
            "invariant": {
                "id": inv.id,
                "description": inv.description,
                "severity": inv.severity,
            },
            "review": None,
            "evidence_level": "PROVEN",
            "path": [],
        })

    severity = _capability_severity(spec, capability)
    if severity is None:
        reason = "Capability is not represented in the current ChangeFence model."
        return _decision(spec, {
            "decision": "REVIEW",
            "origin_agent": origin_agent,
            "executor_agent": executor_agent,
            "capability": capability,
            "severity": None,
            "reason": reason,
            "invariant": None,
            "review": _review_requirement(None, reason=reason),
            "evidence_level": "UNKNOWN",
            "path": [],
        })

    reachable = index_by_pair(analyze(spec))
    item = reachable.get((origin_agent, capability))
    if not item:
        reason = "Capability exists in the model but is not declared reachable from the causal origin."
        return _decision(spec, {
            "decision": "REVIEW",
            "origin_agent": origin_agent,
            "executor_agent": executor_agent,
            "capability": capability,
            "severity": severity,
            "reason": reason,
            "invariant": None,
            "review": _review_requirement(None, reason=reason),
            "evidence_level": "PROVEN",
            "path": [],
        })

    rule = _matching_review_rule(
        spec,
        origin_agent=origin_agent,
        capability=capability,
        severity=severity,
        evidence="PROVEN",
    )
    if rule:
        return _decision(spec, {
            "decision": "REVIEW",
            "origin_agent": origin_agent,
            "executor_agent": executor_agent,
            "capability": capability,
            "severity": severity,
            "reason": rule.reason,
            "invariant": None,
            "review": _review_requirement(rule, reason=rule.reason),
            "evidence_level": "PROVEN",
            "path": list(item.path),
        })

    return _decision(spec, {
        "decision": "ALLOW",
        "origin_agent": origin_agent,
        "executor_agent": executor_agent,
        "capability": capability,
        "severity": severity,
        "reason": "Capability is modeled as reachable and no configured invariant or review rule restricts it.",
        "invariant": None,
        "review": None,
        "evidence_level": "PROVEN",
        "path": list(item.path),
    })


def authorize_action(
    spec: SystemSpec,
    *,
    origin_agent: str,
    capability: str,
    executor_agent: str | None = None,
    approval_lease: dict | None = None,
    approval_secret: str | bytes | None = None,
    usage_path=None,
    now=None,
    consume: bool = True,
) -> dict:
    """Evaluate an action and satisfy REVIEW only with a valid scoped lease.

    A hard invariant can never be overridden. Unknown/unmodeled authority also
    cannot be upgraded to ALLOW by a lease. A usage store is required when a
    lease is consumed so one-time approvals are replay-safe.
    """
    decision = decide_action(
        spec,
        origin_agent=origin_agent,
        capability=capability,
        executor_agent=executor_agent,
    )
    if decision["decision"] != "REVIEW" or approval_lease is None:
        return decision
    if approval_secret is None:
        return {
            **decision,
            "lease_validation": {
                "valid": False,
                "reason": "Approval secret is required to validate a lease.",
            },
        }

    from .approvals import consume_approval_lease, validate_approval_lease

    if consume:
        if usage_path is None:
            return {
                **decision,
                "lease_validation": {
                    "valid": False,
                    "reason": "A usage store is required to consume approval leases safely.",
                },
            }
        validation = consume_approval_lease(
            spec,
            decision,
            approval_lease,
            secret=approval_secret,
            usage_path=usage_path,
            now=now,
        )
    else:
        validation = validate_approval_lease(
            spec,
            decision,
            approval_lease,
            secret=approval_secret,
            usage_path=usage_path,
            now=now,
        )

    if not validation.get("valid"):
        return {**decision, "lease_validation": validation}

    return {
        **decision,
        "decision": "ALLOW",
        "reason": "Configured human review satisfied by a valid scoped approval lease.",
        "review": None,
        "authorization": {
            "type": "APPROVAL_LEASE",
            "lease_id": validation["lease_id"],
            "rule_id": validation["rule_id"],
            "approved_by": validation["approved_by"],
            "approver_group": validation["approver_group"],
            "expires_at": validation["expires_at"],
            "uses": validation["uses"],
            "max_uses": validation["max_uses"],
            "uses_remaining": validation["uses_remaining"],
            "context": validation.get("context", {}),
        },
        "lease_validation": validation,
    }
