#!/usr/bin/env python3
"""Generate the GitHub Pages demo artifacts from the real ChangeFence engine."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from changefence.impact import build_impact_report
from changefence.spec import load_spec

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "demo-data"

SCENARIOS = {
    "procurement-delegation": {
        "title": "Procurement → payment execution",
        "domain": "Finance",
        "change": "+ delegation to Finance Agent",
        "plain_english": "A new delegation edge lets Procurement reach Finance capabilities, including payment execution.",
        "base_file": "examples/procurement-base.yaml",
        "candidate_file": "examples/procurement-candidate.yaml",
    },
    "support-pii-export": {
        "title": "Support → customer PII export",
        "domain": "Data",
        "change": "+ delegation to Analytics Agent",
        "plain_english": "A new delegation edge lets Support reach Analytics capabilities, including customer PII export.",
        "base_file": "examples/support-base.yaml",
        "candidate_file": "examples/support-candidate.yaml",
    },
    "coding-production-deploy": {
        "title": "Coding agent → production deploy",
        "domain": "Production",
        "change": "+ deploy tool",
        "plain_english": "Adding the deploy tool makes production deployment directly reachable by the coding agent.",
        "base_file": "examples/coding-base.yaml",
        "candidate_file": "examples/coding-candidate.yaml",
    },
    "safe-prompt-update": {
        "title": "Prompt-only safe change",
        "domain": "Control",
        "change": "prompt_id updated; authority unchanged",
        "plain_english": "The prompt reference changed, but no new modeled capability or forbidden path was introduced.",
        "base_file": "examples/procurement-base.yaml",
        "candidate_file": "examples/procurement-safe-candidate.yaml",
    },
}


def render(slug: str, config: dict) -> str:
    base = load_spec(ROOT / config["base_file"])
    candidate = load_spec(ROOT / config["candidate_file"])
    result = build_impact_report(base, candidate, use_llm=False)
    payload = {"scenario": slug, **config, "result": result}
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail if committed demo data differs from engine output")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    drift = []
    for slug, config in SCENARIOS.items():
        path = OUT / f"{slug}.json"
        expected = render(slug, config)
        if args.check:
            actual = path.read_text(encoding="utf-8") if path.exists() else ""
            if actual != expected:
                drift.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(expected, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
    if drift:
        print("Demo artifacts are stale. Regenerate with: python scripts/generate_demo_results.py")
        for path in drift:
            print(f"- {path}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
