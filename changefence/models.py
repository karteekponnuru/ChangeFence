from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass(frozen=True)
class Capability:
    name: str
    severity: str = "medium"
    description: str = ""


@dataclass(frozen=True)
class Tool:
    name: str
    capabilities: tuple[Capability, ...] = ()


@dataclass
class Agent:
    name: str
    tools: List[str] = field(default_factory=list)
    delegates_to: List[str] = field(default_factory=list)
    model: str = ""
    prompt_id: str = ""


@dataclass(frozen=True)
class Invariant:
    id: str
    description: str
    source_agent: str
    forbidden_capability: str
    severity: str = "critical"


@dataclass(frozen=True)
class ReviewRule:
    id: str
    origin_agent: str = "*"
    capability: str = "*"
    severity_at_least: str = "low"
    evidence: str = "*"
    approver: str = "security"
    expires_minutes: int = 15
    max_uses: int = 1
    reason: str = "Security review required before execution."


@dataclass(frozen=True)
class PolicyAuthority:
    name: str
    version: str
    owner: str
    source: str = ""
    approved_by: str = ""
    effective_from: str = ""
    digest: str = ""


@dataclass
class SystemSpec:
    name: str
    agents: Dict[str, Agent]
    tools: Dict[str, Tool]
    invariants: List[Invariant]
    review_rules: List[ReviewRule] = field(default_factory=list)
    policy_authority: PolicyAuthority | None = None


@dataclass(frozen=True)
class Reachability:
    source_agent: str
    capability: str
    severity: str
    path: tuple[str, ...]


@dataclass
class AnalysisResult:
    reachable: Set[Reachability]
