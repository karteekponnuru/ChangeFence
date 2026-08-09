"""Small, deterministic descriptor readers used to ground semantic inference."""
from __future__ import annotations

import json
from pathlib import Path
import yaml


class DescriptorError(ValueError):
    pass


def _read(path: Path):
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise DescriptorError(f"Descriptor not found: {path}") from exc
    try:
        if path.suffix.lower() in {".yaml", ".yml"}:
            return yaml.safe_load(text), text
        return json.loads(text), text
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise DescriptorError(f"Invalid descriptor {path}: {exc}") from exc


def _openapi_summary(data: dict, source: str) -> dict:
    operations = []
    for route, path_item in (data.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"} or not isinstance(operation, dict):
                continue
            operations.append({
                "method": method.upper(),
                "path": str(route),
                "operation_id": str(operation.get("operationId", "")),
                "summary": str(operation.get("summary", "")),
                "description": str(operation.get("description", ""))[:500],
                "security": operation.get("security", []),
            })
    return {"source": source, "type": "openapi", "title": str((data.get("info") or {}).get("title", "")), "operations": operations[:250]}


def _mcp_summary(data: dict, source: str) -> dict:
    tools_raw = data.get("tools") or []
    tools = []
    if isinstance(tools_raw, dict):
        tools_raw = [{"name": name, **(cfg if isinstance(cfg, dict) else {})} for name, cfg in tools_raw.items()]
    for tool in tools_raw:
        if not isinstance(tool, dict):
            continue
        tools.append({
            "name": str(tool.get("name", "")),
            "description": str(tool.get("description", ""))[:1000],
            "input_schema": tool.get("inputSchema", tool.get("input_schema", {})),
        })
    return {"source": source, "type": "mcp_tools", "tools": tools[:250]}


def summarize_descriptor(path: str | Path) -> dict:
    path = Path(path)
    data, text = _read(path)
    if not isinstance(data, dict):
        return {"source": str(path), "type": "generic", "content": text[:12000]}
    if "openapi" in data or "swagger" in data:
        return _openapi_summary(data, str(path))
    if "tools" in data:
        return _mcp_summary(data, str(path))
    return {"source": str(path), "type": "generic", "content": json.dumps(data, ensure_ascii=False)[:12000]}


def build_descriptor_context(paths: list[str] | None) -> str:
    if not paths:
        return ""
    summaries = [summarize_descriptor(path) for path in paths]
    return json.dumps({"descriptors": summaries}, indent=2, ensure_ascii=False)
