from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .impact import build_impact_report
from .runtime import RuntimeDecisionError, decide_action
from .spec import SpecError, load_spec, policy_authority_dict

ROOT = Path(__file__).resolve().parents[1]
PLAYGROUND = ROOT / "playground"

app = FastAPI(
    title="ChangeFence Playground",
    version="0.1.0",
    description="Interactive API for exploring ChangeFence authority changes and runtime policy decisions.",
)


class AnalyzeRequest(BaseModel):
    baseline: str = Field(min_length=1, max_length=120_000)
    candidate: str = Field(min_length=1, max_length=120_000)
    policy: str = Field(min_length=1, max_length=80_000)
    fail_on: str = "high"


class RuntimeRequest(BaseModel):
    spec: str = Field(min_length=1, max_length=120_000)
    policy: str = Field(min_length=1, max_length=80_000)
    origin_agent: str = Field(min_length=1, max_length=200)
    capability: str = Field(min_length=1, max_length=300)
    executor_agent: str | None = Field(default=None, max_length=200)


def _write_inputs(temp: Path, *, baseline: str | None = None, candidate: str | None = None, spec: str | None = None, policy: str) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    if baseline is not None:
        paths["baseline"] = temp / "baseline.yaml"
        paths["baseline"].write_text(baseline, encoding="utf-8")
    if candidate is not None:
        paths["candidate"] = temp / "candidate.yaml"
        paths["candidate"].write_text(candidate, encoding="utf-8")
    if spec is not None:
        paths["spec"] = temp / "spec.yaml"
        paths["spec"].write_text(spec, encoding="utf-8")
    paths["policy"] = temp / "policy.yaml"
    paths["policy"].write_text(policy, encoding="utf-8")
    return paths


def _graph_payload(spec) -> dict[str, Any]:
    nodes = []
    edges = []
    for agent_name, agent in spec.agents.items():
        nodes.append({"id": f"agent:{agent_name}", "label": agent_name, "type": "agent"})
        for delegated in agent.delegates_to:
            edges.append({
                "from": f"agent:{agent_name}",
                "to": f"agent:{delegated}",
                "type": "delegation",
                "label": "delegates",
            })
        for tool_name in agent.tools:
            tool_id = f"tool:{tool_name}"
            if not any(node["id"] == tool_id for node in nodes):
                nodes.append({"id": tool_id, "label": tool_name, "type": "tool"})
            edges.append({"from": f"agent:{agent_name}", "to": tool_id, "type": "tool_access", "label": "uses"})
            for capability in spec.tools[tool_name].capabilities:
                cap_id = f"cap:{capability.name}"
                if not any(node["id"] == cap_id for node in nodes):
                    nodes.append({
                        "id": cap_id,
                        "label": capability.name,
                        "type": "capability",
                        "severity": capability.severity,
                    })
                edges.append({"from": tool_id, "to": cap_id, "type": "capability", "label": "enables"})
    return {"nodes": nodes, "edges": edges}


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "product": "ChangeFence Playground"}


@app.post("/api/analyze")
def analyze_change(payload: AnalyzeRequest) -> dict[str, Any]:
    if payload.fail_on not in {"low", "medium", "high", "critical"}:
        raise HTTPException(status_code=400, detail="fail_on must be low, medium, high, or critical")
    try:
        with TemporaryDirectory(prefix="changefence-playground-") as directory:
            paths = _write_inputs(
                Path(directory),
                baseline=payload.baseline,
                candidate=payload.candidate,
                policy=payload.policy,
            )
            baseline = load_spec(paths["baseline"], policy_path=paths["policy"])
            candidate = load_spec(paths["candidate"], policy_path=paths["policy"])
            report = build_impact_report(baseline, candidate, fail_on=payload.fail_on, use_llm=False)
            graph = _graph_payload(candidate)
    except SpecError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    primary_path = []
    if report["structural"]["gate_violations"]:
        primary_path = report["structural"]["gate_violations"][0].get("path", [])
    elif report["proven_findings"]:
        primary_path = report["proven_findings"][0].get("path", [])

    return {
        "decision": report["decision"],
        "reason": report["decision_reason"],
        "policy_authority": report.get("policy_authority"),
        "summary": report["summary"],
        "new_capabilities": report["proven_findings"],
        "violations": report["structural"]["gate_violations"],
        "structural_changes": report["structural"]["structural_diff"]["changes"],
        "primary_path": primary_path,
        "graph": graph,
        "evidence_contract": report["evidence_contract"],
    }


@app.post("/api/runtime")
def runtime_decision(payload: RuntimeRequest) -> dict[str, Any]:
    try:
        with TemporaryDirectory(prefix="changefence-runtime-") as directory:
            paths = _write_inputs(Path(directory), spec=payload.spec, policy=payload.policy)
            spec = load_spec(paths["spec"], policy_path=paths["policy"])
            decision = decide_action(
                spec,
                origin_agent=payload.origin_agent,
                executor_agent=payload.executor_agent,
                capability=payload.capability,
            )
    except (SpecError, RuntimeDecisionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return decision


@app.get("/api/example")
def example() -> dict[str, str]:
    return {
        "baseline": (ROOT / "examples" / "procurement-agents-base.yaml").read_text(encoding="utf-8"),
        "candidate": (ROOT / "examples" / "procurement-agents-candidate.yaml").read_text(encoding="utf-8"),
        "policy": (ROOT / "examples" / "acme-security-policy.yaml").read_text(encoding="utf-8"),
    }


if PLAYGROUND.exists():
    app.mount("/assets", StaticFiles(directory=PLAYGROUND), name="playground-assets")


@app.get("/")
def index():
    return FileResponse(PLAYGROUND / "index.html")
