from collections import deque
from .models import AnalysisResult, Reachability, SystemSpec

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def analyze(spec: SystemSpec) -> AnalysisResult:
    """Compute every capability each agent can reach directly or through delegation."""
    reachable: set[Reachability] = set()

    for source in spec.agents:
        q = deque([(source, (source,))])
        visited = set()

        while q:
            agent_name, path = q.popleft()
            if agent_name in visited:
                continue
            visited.add(agent_name)
            agent = spec.agents.get(agent_name)
            if not agent:
                continue

            for tool_name in agent.tools:
                tool = spec.tools[tool_name]
                for cap in tool.capabilities:
                    reachable.add(
                        Reachability(
                            source_agent=source,
                            capability=cap.name,
                            severity=cap.severity,
                            path=path + (f"tool:{tool_name}", f"cap:{cap.name}"),
                        )
                    )

            for delegated in agent.delegates_to:
                if delegated not in visited:
                    q.append((delegated, path + (f"delegate:{delegated}", delegated)))

    return AnalysisResult(reachable=reachable)


def index_by_pair(result: AnalysisResult):
    index = {}
    for item in result.reachable:
        key = (item.source_agent, item.capability)
        if key not in index or len(item.path) < len(index[key].path):
            index[key] = item
    return index


def _structural_diff(base: SystemSpec, candidate: SystemSpec) -> dict:
    changes = []
    base_agents = set(base.agents)
    cand_agents = set(candidate.agents)

    for name in sorted(cand_agents - base_agents):
        changes.append({"type": "agent_added", "agent": name, "risk": "review"})
    for name in sorted(base_agents - cand_agents):
        changes.append({"type": "agent_removed", "agent": name, "risk": "info"})

    for name in sorted(base_agents & cand_agents):
        before, after = base.agents[name], candidate.agents[name]
        if before.model != after.model:
            changes.append({"type": "model_changed", "agent": name, "before": before.model, "after": after.model, "risk": "review"})
        if before.prompt_id != after.prompt_id:
            changes.append({"type": "prompt_changed", "agent": name, "before": before.prompt_id, "after": after.prompt_id, "risk": "review"})
        for tool in sorted(set(after.tools) - set(before.tools)):
            changes.append({"type": "tool_added", "agent": name, "tool": tool, "risk": "review"})
        for tool in sorted(set(before.tools) - set(after.tools)):
            changes.append({"type": "tool_removed", "agent": name, "tool": tool, "risk": "info"})
        for target in sorted(set(after.delegates_to) - set(before.delegates_to)):
            changes.append({"type": "delegation_added", "agent": name, "target": target, "risk": "high"})
        for target in sorted(set(before.delegates_to) - set(after.delegates_to)):
            changes.append({"type": "delegation_removed", "agent": name, "target": target, "risk": "info"})

    return {"changes": changes, "count": len(changes)}


def compare(base: SystemSpec, candidate: SystemSpec, fail_on: str = "high") -> dict:
    base_result = analyze(base)
    cand_result = analyze(candidate)
    base_idx = index_by_pair(base_result)
    cand_idx = index_by_pair(cand_result)

    new_pairs = sorted(set(cand_idx) - set(base_idx))
    removed_pairs = sorted(set(base_idx) - set(cand_idx))

    violations = []
    for inv in candidate.invariants:
        pair = (inv.source_agent, inv.forbidden_capability)
        if pair in cand_idx:
            violations.append({
                "id": inv.id,
                "description": inv.description,
                "source_agent": inv.source_agent,
                "capability": inv.forbidden_capability,
                "severity": inv.severity,
                "path": list(cand_idx[pair].path),
                "new_in_candidate": pair not in base_idx,
            })

    new_capabilities = []
    for src, cap in new_pairs:
        item = cand_idx[(src, cap)]
        new_capabilities.append({"source_agent": src, "capability": cap, "severity": item.severity, "path": list(item.path)})

    removed_capabilities = []
    for src, cap in removed_pairs:
        item = base_idx[(src, cap)]
        removed_capabilities.append({"source_agent": src, "capability": cap, "severity": item.severity, "path": list(item.path)})

    new_violations = [v for v in violations if v["new_in_candidate"]]
    threshold = SEVERITY_RANK[fail_on]
    gate_violations = [v for v in new_violations if SEVERITY_RANK[v["severity"]] >= threshold]
    high_risk_new_caps = [x for x in new_capabilities if SEVERITY_RANK[x["severity"]] >= threshold]
    status = "FAIL" if gate_violations else "PASS"

    structural = _structural_diff(base, candidate)

    return {
        "status": status,
        "base": base.name,
        "candidate": candidate.name,
        "fail_on": fail_on,
        "structural_diff": structural,
        "new_capabilities": new_capabilities,
        "removed_capabilities": removed_capabilities,
        "violations": violations,
        "new_security_regressions": new_violations,
        "gate_violations": gate_violations,
        "high_risk_new_capabilities": high_risk_new_caps,
        "summary": {
            "structural_changes": structural["count"],
            "new_capabilities": len(new_capabilities),
            "removed_capabilities": len(removed_capabilities),
            "invariant_violations": len(violations),
            "new_security_regressions": len(new_violations),
            "gate_violations": len(gate_violations),
            "high_risk_new_capabilities": len(high_risk_new_caps),
        },
    }
