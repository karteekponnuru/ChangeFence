"""LLM-assisted semantic analysis for ChangeFence.

The LLM is deliberately restricted to proposing semantic facts and risks. Those
proposals are never promoted to deterministic proof by this module.
"""
from __future__ import annotations

import copy
import json
import re
import urllib.error
import urllib.request
from dataclasses import asdict

from .models import Capability, SystemSpec, Tool


class SemanticError(RuntimeError):
    pass


CONFIDENCE = {"low": 1, "medium": 2, "high": 3}
SEVERITIES = {"low", "medium", "high", "critical"}
CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")


SEMANTIC_SCHEMA = {
    "type": "object",
    "properties": {
        "capability_mappings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "tool": {"type": "string"},
                    "capability": {"type": "string"},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                    "applies_to": {"type": "string", "enum": ["baseline", "candidate", "both"]},
                    "evidence": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["tool", "capability", "severity", "confidence", "applies_to", "evidence", "rationale"],
            },
        },
        "semantic_risks": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "agent": {"type": "string"},
                    "change_type": {"type": "string"},
                    "affected_capability": {"type": "string"},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                    "evidence": {"type": "string"},
                    "rationale": {"type": "string"},
                    "recommended_verification": {"type": "string"},
                },
                "required": ["id", "agent", "change_type", "affected_capability", "severity", "confidence", "evidence", "rationale", "recommended_verification"],
            },
        },
    },
    "required": ["capability_mappings", "semantic_risks"],
}


def _architecture(spec: SystemSpec) -> dict:
    return {
        "system": spec.name,
        "agents": {
            name: {"model": agent.model, "prompt_id": agent.prompt_id, "tools": list(agent.tools), "delegates_to": list(agent.delegates_to)}
            for name, agent in spec.agents.items()
        },
        "tools": {name: {"capabilities": [asdict(cap) for cap in tool.capabilities]} for name, tool in spec.tools.items()},
        "invariants": [asdict(inv) for inv in spec.invariants],
    }


def build_semantic_prompt(base: SystemSpec, candidate: SystemSpec, diff_text: str = "", repository_context: str = "") -> str:
    payload = {"baseline": _architecture(base), "candidate": _architecture(candidate), "source_diff": diff_text[:30000], "repository_context": repository_context[:20000]}
    return f"""
You are the semantic change compiler for ChangeFence, a defensive AI-agent security tool.
Your job is to translate messy repository changes into REVIEWABLE security facts. You are NOT the security verdict engine.

Return two kinds of proposals:
1. capability_mappings: normalize tool/API/MCP operations into concise capabilities such as payment.execute, customer.pii.read, production.deploy. Only propose a mapping when the supplied architecture/diff contains concrete evidence for it. If the tool exists in both releases, use applies_to=both unless the operation itself is newly introduced.
2. semantic_risks: identify security-relevant prompt/model/instruction changes that may alter when an ALREADY AVAILABLE capability is exercised. These are hypotheses requiring runtime verification, never proof of new authority.

Hard rules:
- Never invent agents or tools that are absent from baseline/candidate.
- capability must be lower-case dot notation (letters, numbers, _, -, :, . only).
- Evidence must quote or point to a concrete supplied identifier, endpoint, function, tool description, prompt line, config key, or diff hunk. Do not use generic reasoning as evidence.
- For semantic_risks, affected_capability must be a capability already declared in either system or proposed in capability_mappings.
- If evidence is insufficient, omit the proposal.
- Every output from you is HYPOTHESIZED until ChangeFence independently verifies it.
- Return only JSON matching the requested schema.

INPUT:\n{json.dumps(payload, indent=2)}
""".strip()


def _ollama_structured_request(*, model: str, prompt: str, schema: dict, base_url: str = "http://localhost:11434", timeout: int = 120) -> dict:
    endpoint = base_url.rstrip("/") + "/api/chat"
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You extract defensive security hypotheses. Never convert an inference into a verified fact."},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "format": schema,
        "options": {"temperature": 0},
    }
    request = urllib.request.Request(endpoint, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise SemanticError(f"Could not reach Ollama at {base_url}. ({exc})") from exc
    except json.JSONDecodeError as exc:
        raise SemanticError("Ollama returned invalid JSON.") from exc
    try:
        return json.loads(raw["message"]["content"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SemanticError("Ollama response did not match the expected structured-output envelope.") from exc


def _declared_capabilities(*specs: SystemSpec) -> set[str]:
    return {cap.name for spec in specs for tool in spec.tools.values() for cap in tool.capabilities}


def sanitize_semantic_output(base: SystemSpec, candidate: SystemSpec, raw: dict) -> dict:
    """Fail closed: retain only proposals grounded in known agents/tools/capabilities."""
    if not isinstance(raw, dict):
        raise SemanticError("Semantic output must be an object.")
    all_tools = set(base.tools) | set(candidate.tools)
    all_agents = set(base.agents) | set(candidate.agents)
    declared = _declared_capabilities(base, candidate)
    mappings = []
    seen_mapping = set()
    for item in raw.get("capability_mappings", []):
        if not isinstance(item, dict):
            continue
        tool = str(item.get("tool", "")).strip()
        cap = str(item.get("capability", "")).strip().lower()
        severity = str(item.get("severity", "medium")).lower()
        confidence = str(item.get("confidence", "low")).lower()
        applies_to = str(item.get("applies_to", "candidate")).lower()
        evidence = str(item.get("evidence", "")).strip()
        rationale = str(item.get("rationale", "")).strip()
        if tool not in all_tools or not CAPABILITY_RE.fullmatch(cap):
            continue
        if severity not in SEVERITIES or confidence not in CONFIDENCE or applies_to not in {"baseline", "candidate", "both"}:
            continue
        if len(evidence) < 4:
            continue
        if applies_to in {"baseline", "both"} and tool not in base.tools:
            continue
        if applies_to in {"candidate", "both"} and tool not in candidate.tools:
            continue
        key = (tool, cap, applies_to)
        if key in seen_mapping:
            continue
        seen_mapping.add(key)
        mappings.append({"tool": tool, "capability": cap, "severity": severity, "confidence": confidence, "applies_to": applies_to, "evidence": evidence, "rationale": rationale, "evidence_level": "HYPOTHESIZED"})
    known_caps = declared | {m["capability"] for m in mappings}
    risks = []
    seen_risk = set()
    for item in raw.get("semantic_risks", []):
        if not isinstance(item, dict):
            continue
        rid = str(item.get("id", "")).strip() or f"SEM-{len(risks)+1:03d}"
        agent = str(item.get("agent", "")).strip()
        cap = str(item.get("affected_capability", "")).strip().lower()
        severity = str(item.get("severity", "medium")).lower()
        confidence = str(item.get("confidence", "low")).lower()
        evidence = str(item.get("evidence", "")).strip()
        if agent not in all_agents or cap not in known_caps:
            continue
        if severity not in SEVERITIES or confidence not in CONFIDENCE or len(evidence) < 4:
            continue
        key = (agent, cap, str(item.get("change_type", "")))
        if key in seen_risk:
            continue
        seen_risk.add(key)
        risks.append({"id": rid, "agent": agent, "change_type": str(item.get("change_type", "semantic_change")).strip() or "semantic_change", "affected_capability": cap, "severity": severity, "confidence": confidence, "evidence": evidence, "rationale": str(item.get("rationale", "")).strip(), "recommended_verification": str(item.get("recommended_verification", "")).strip(), "evidence_level": "HYPOTHESIZED", "requires_runtime_verification": True})
    return {"capability_mappings": mappings, "semantic_risks": risks, "summary": {"capability_mappings": len(mappings), "semantic_risks": len(risks)}}


def analyze_semantic_change(base: SystemSpec, candidate: SystemSpec, *, diff_text: str = "", repository_context: str = "", model: str = "gemma3", base_url: str = "http://localhost:11434", timeout: int = 120, requester=None) -> dict:
    prompt = build_semantic_prompt(base, candidate, diff_text=diff_text, repository_context=repository_context)
    if requester is None:
        raw = _ollama_structured_request(model=model, prompt=prompt, schema=SEMANTIC_SCHEMA, base_url=base_url, timeout=timeout)
    else:
        raw = requester(model=model, prompt=prompt, schema=SEMANTIC_SCHEMA, base_url=base_url, timeout=timeout)
    result = sanitize_semantic_output(base, candidate, raw)
    return {"engine": "ollama", "model": model, **result}


def _with_mapping(spec: SystemSpec, mapping: dict) -> SystemSpec:
    if mapping["tool"] not in spec.tools:
        return spec
    cloned = copy.deepcopy(spec)
    tool = cloned.tools[mapping["tool"]]
    if any(cap.name == mapping["capability"] for cap in tool.capabilities):
        return cloned
    new_cap = Capability(name=mapping["capability"], severity=mapping["severity"], description=f"LLM-proposed mapping; evidence: {mapping['evidence']}")
    cloned.tools[mapping["tool"]] = Tool(name=tool.name, capabilities=tuple(tool.capabilities) + (new_cap,))
    return cloned


def build_inferred_specs(base: SystemSpec, candidate: SystemSpec, mappings: list[dict], min_confidence: str = "high") -> tuple[SystemSpec, SystemSpec, list[dict]]:
    """Build a shadow graph from high-confidence mappings without mutating source specs."""
    threshold = CONFIDENCE[min_confidence]
    b, c = copy.deepcopy(base), copy.deepcopy(candidate)
    applied = []
    for mapping in mappings:
        if CONFIDENCE.get(mapping.get("confidence", "low"), 0) < threshold:
            continue
        applies = mapping["applies_to"]
        if applies in {"baseline", "both"}:
            b = _with_mapping(b, mapping)
        if applies in {"candidate", "both"}:
            c = _with_mapping(c, mapping)
        applied.append(mapping)
    return b, c, applied
