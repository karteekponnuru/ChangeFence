from pathlib import Path
import yaml
from .models import Agent, Capability, Invariant, ReviewRule, SystemSpec, Tool

ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
ALLOWED_EVIDENCE = {"*", "UNKNOWN", "PROVEN", "HYPOTHESIZED", "VERIFIED"}


class SpecError(ValueError):
    pass


def _severity(value: str | None, default: str = "medium") -> str:
    value = (value or default).lower()
    if value not in ALLOWED_SEVERITIES:
        raise SpecError(f"Unsupported severity '{value}'. Use low, medium, high, or critical.")
    return value


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


def load_spec(path: str | Path) -> SystemSpec:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError as exc:
        raise SpecError(f"Spec not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise SpecError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise SpecError(f"Top-level spec in {path} must be a mapping.")

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

    review_rules = [_parse_review_rule(item) for item in raw.get("reviews", [])]

    spec = SystemSpec(
        name=str(raw.get("system", path.stem)),
        agents=agents,
        tools=tools,
        invariants=invariants,
        review_rules=review_rules,
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
