"""Translate ChangeFence findings into reviewable enforcement plans."""
from __future__ import annotations


def build_policy_plan(impact_report: dict) -> dict:
    recommendations = []
    violations = impact_report.get("structural", {}).get("gate_violations", [])
    for index, violation in enumerate(violations, start=1):
        source = violation["source_agent"]
        capability = violation["capability"]
        recommendations.append({
            "id": f"CF-POL-{index:03d}",
            "status": "REVIEW_REQUIRED",
            "severity": violation["severity"],
            "intent": f"Prevent {source} from causing {capability}.",
            "causal_origin": source,
            "capability": capability,
            "triggered_by_invariant": violation["id"],
            "evidence_path": violation.get("path", []),
            "control_options": [
                "Remove or narrow the authority edge that introduced the path.",
                "Require explicit human approval before the sensitive capability executes.",
                "Add a runtime deny rule for this causal-origin/capability combination.",
            ],
            "enforcement_targets": [
                "ChangeFence Runtime for custom/local agents",
                "AWS AgentCore Policy for AWS-hosted agent gateways",
                "Google Agent Gateway / governance controls for Google-hosted agents",
            ],
            "auto_deploy": False,
        })

    return {
        "product": "ChangeFence Policy",
        "base": impact_report.get("base"),
        "candidate": impact_report.get("candidate"),
        "source_decision": impact_report.get("decision"),
        "recommendations": recommendations,
        "summary": {"recommendations": len(recommendations)},
        "safety_contract": "Policy plans are recommendations for review; ChangeFence does not silently deploy generated controls.",
    }
