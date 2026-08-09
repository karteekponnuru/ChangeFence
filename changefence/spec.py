from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

from .models import Agent, Capability, Invariant, PolicyAuthority, ReviewRule, SystemSpec, Tool

ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
ALLOWED_EVIDENCE = {"*", "UNKNOWN", "PROVEN", "HYPOTHESIZED", "VERIFIED"}


class SpecError(ValueError):
    pass


def _severity(value: str | None, default: str = "medium") -> str:
    value = (value or default).lower()
    if value not in ALLOWED_SEVERITIES:
        raise SpecError(f"Unsupported severity '{value}'. Use low, medium, high, or critical.")
    return value


def _load_yaml(path: str | Path) -> tuple[Path, dict]:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError as exc:
        raise SpecError(f"Spec not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise SpecError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise SpecError(f"Top-level YAML in {path} must be a mapping.")
    return path, raw


def _parse_capability(item) -> Capability:
    if isinstance(item, str):
        return Capability(name=item)
    if not isinstance(item, dict) or not item.get("name"):
        raise SpecError("Tool capabilities must be strings or objects with a name field.")
    return Capability(
        name=str(item["name"]),
        severity=_severity(item.get("severity")),
        description=str(item.get("description", "")),
    )


def _parse_review_rule(item) -> ReviewRule:
    if not isinstance(item, dict) or not item.get("id"):
        raise SpecError("Each review rule requires an id.")
    match = item.get("match", {}) or {}
    require = item.get("require", {}) or {}
    evidence = str(match.get("evidence", "*")).upper()
    if evidence not in ALLOWED_EVIDENCE:
        raise SpecError(
            f"Review rule '{item['id']}' has unsupported evidence '{evidence}'. "
            "Use *, UNKNOWN, PROVEN, HYPOTHESIZED, or VERIFIED."
        )
    expires_minutes = int(require.get("expires_minutes", 15))
    max_uses = int(require.get("max_uses", 1))
    if expires_minutes <= 0 or max_uses <= 0:
        raise SpecError(f"Review rule '{item['id']}' requires positive expires_minutes and max_uses.")
    return ReviewRule(
        id=str(item["id"]),
        origin_agent=str(match.get("origin", "*")),
        capability=str(match.get("capability", "*")),
        severity_at_least=_severity(match.get("severity_at_least"), "low"),
        evidence=evidence,
        approver=str(require.get("approver", "security")),
        expires_minutes=expires_minutes,
        max_uses=max_uses,
        reason=str(require.get("reason", "Security review required before execution.")),
    )


def _parse_invariants(raw: dict) -> list[Invariant]:
    invariants = []
    for inv in raw.get("invariants", []):
        if "forbid_reachability" not in inv:
            raise SpecError(f"Invariant {inv.get('id', '<unknown>')} is missing forbid_reachability.")
        rule = inv["forbid_reachability"]
        invariants.append(
            Invariant(
                id=str(inv["id"]),
                description=str(inv.get("description", "")),
                source_agent=str(rule["from"]),
                forbidden_capability=str(rule["to"]),
                severity=_severity(inv.get("severity"), "critical"),
            )
        )
    return invariants


def _policy_digest(raw: dict) -> str:
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _parse_policy_authority(path: Path, raw: dict) -> PolicyAuthority:
    if "agents" in raw or "tools" in raw:
        raise SpecError(
            f"Policy registry {path} must contain security policy only; agents/tools belong in the developer-controlled agent spec."
        )
    meta = raw.get("policy")
    if not isinstance(meta, dict):
        raise SpecError(f"Policy registry {path} requires a top-level 'policy' metadata block.")
    missing = [field for field in ("name", "version", "owner") if not str(meta.get(field, "")).strip()]
    if missing:
        raise SpecError(f"Policy registry {path} is missing required metadata: {', '.join(missing)}.")
    return PolicyAuthority(
        name=str(meta["name"]).strip(),
        version=str(meta["version"]).strip(),
        owner=str(meta["owner"]).strip(),
        source=str(meta.get("source", "")).strip(),
        approved_by=str(meta.get("approved_by", "")).strip(),
        effective_from=str(meta.get("effective_from", "")).strip(),
        digest=_policy_digest(raw),
    )


def policy_authority_dict(spec: SystemSpec) -> dict | None:
    authority = spec.policy_authority
    if authority is None:
        return None
    return {
        "name": authority.name,
        "version": authority.version,
        "owner": authority.owner,
        "source": authority.source,
        "approved_by": authority.approved_by,
        "effective_from": authority.effective_from,
        "digest": authority.digest,
    }


def load_spec(path: str | Path, policy_path: str | Path | None = None) -> SystemSpec:
    path, raw = _load_yaml(path)

    agents = {
        name: Agent(
            name=name,
            tools=list(cfg.get("tools", [])),
            delegates_to=list(cfg.get("delegates_to", [])),
            model=str(cfg.get("model", "")),
            prompt_id=str(cfg.get("prompt_id", "")),
        )
        for name, cfg in raw.get("agents", {}).items()
    }

    tools = {}
    for name, cfg in raw.get("tools", {}).items():
        caps = tuple(_parse_capability(item) for item in cfg.get("capabilities", []))
        tools[name] = Tool(name=name, capabilities=caps)

    policy_authority = None
    policy_raw = raw
    if policy_path is not None:
        policy_file, policy_raw = _load_yaml(policy_path)
        policy_authority = _parse_policy_authority(policy_file, policy_raw)

    # External policy is the sole security ground truth when supplied.
    # Developer-embedded invariants/reviews are intentionally ignored.
    invariants = _parse_invariants(policy_raw)
    review_rules = [_parse_review_rule(item) for item in policy_raw.get("reviews", [])]

    spec = SystemSpec(
        name=str(raw.get("system", path.stem)),
        agents=agents,
        tools=tools,
        invariants=invariants,
        review_rules=review_rules,
        policy_authority=policy_authority,
    )
    validate_spec(spec)
    return spec


def validate_spec(spec: SystemSpec) -> None:
    for agent in spec.agents.values():
        for tool in agent.tools:
            if tool not in spec.tools:
                raise SpecError(f"Agent '{agent.name}' references unknown tool '{tool}'.")
        for target in agent.delegates_to:
            if target not in spec.agents:
                raise SpecError(f"Agent '{agent.name}' delegates to unknown agent '{target}'.")

    for inv in spec.invariants:
        if inv.source_agent not in spec.agents:
            raise SpecError(f"Invariant '{inv.id}' references unknown agent '{inv.source_agent}'.")

    for rule in spec.review_rules:
        if rule.origin_agent != "*" and rule.origin_agent not in spec.agents:
            raise SpecError(f"Review rule '{rule.id}' references unknown origin agent '{rule.origin_agent}'.")
