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


@dataclass
class SystemSpec:
    name: str
    agents: Dict[str, Agent]
    tools: Dict[str, Tool]
    invariants: List[Invariant]


@dataclass(frozen=True)
class Reachability:
    source_agent: str
    capability: str
    severity: str
    path: tuple[str, ...]


@dataclass
class AnalysisResult:
    reachable: Set[Reachability]
