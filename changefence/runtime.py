"""Runtime decision hook for custom/local agent execution paths.

This is intentionally small: it is not a replacement for cloud-native gateways.
It gives custom agent systems a deterministic pre-action decision using the same
invariants and authority model as ChangeFence Impact.
"""
from __future__ import annotations

from .engine import analyze, index_by_pair
from .models import SystemSpec


class RuntimeDecisionError(ValueError):
    pass


def decide_action(
    spec: SystemSpec,
    *,
    origin_agent: str,
    capability: str,
    executor_agent: str | None = None,
) -> dict:
    """Return ALLOW, REVIEW, or BLOCK before a security-relevant action executes.

    BLOCK is reserved for an explicit invariant violation. REVIEW is used when
    ChangeFence cannot establish that the requested capability is represented and
    reachable in the current model. This prevents model incompleteness from being
    mislabeled as either authorization or malicious behavior.
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
        return {
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
            "evidence_level": "PROVEN",
            "path": [],
        }

    known_capabilities = {
        cap.name
        for tool in spec.tools.values()
        for cap in tool.capabilities
    }
    if capability not in known_capabilities:
        return {
            "decision": "REVIEW",
            "origin_agent": origin_agent,
            "executor_agent": executor_agent,
            "capability": capability,
            "reason": "Capability is not represented in the current ChangeFence model.",
            "invariant": None,
            "evidence_level": "UNKNOWN",
            "path": [],
        }

    reachable = index_by_pair(analyze(spec))
    item = reachable.get((origin_agent, capability))
    if not item:
        return {
            "decision": "REVIEW",
            "origin_agent": origin_agent,
            "executor_agent": executor_agent,
            "capability": capability,
            "reason": "Capability exists in the model but is not declared reachable from the causal origin.",
            "invariant": None,
            "evidence_level": "PROVEN",
            "path": [],
        }

    return {
        "decision": "ALLOW",
        "origin_agent": origin_agent,
        "executor_agent": executor_agent,
        "capability": capability,
        "reason": "Capability is modeled as reachable and no configured invariant forbids it.",
        "invariant": None,
        "evidence_level": "PROVEN",
        "path": list(item.path),
    }
