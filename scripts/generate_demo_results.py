#!/usr/bin/env python3
"""Generate the GitHub Pages demo artifacts from the real ChangeFence engines."""
from __future__ import annotations

import argparse
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from changefence.approvals import issue_approval_lease
from changefence.impact import build_impact_report
from changefence.policy import build_policy_plan
from changefence.runtime import authorize_action, decide_action
from changefence.spec import load_spec

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "demo-data"
DEMO_SECRET = "changefence-demo-only-secret-not-for-production-2026"
DEMO_TIME = datetime(2026, 8, 9, 22, 30, tzinfo=timezone.utc)

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


def _impact_payload(slug: str, config: dict) -> str:
    base = load_spec(ROOT / config["base_file"])
    candidate = load_spec(ROOT / config["candidate_file"])
    report = build_impact_report(base, candidate, use_llm=False)
    result = {
        "decision": report["decision"],
        "decision_reason": report["decision_reason"],
        "summary": report["summary"],
        "proven_findings": report["proven_findings"],
        "gate_violations": report["structural"]["gate_violations"],
        "structural_changes": report["structural"]["structural_diff"]["changes"],
        "evidence_contract": report["evidence_contract"],
    }
    payload = {"scenario": slug, **config, "result": result}
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _suite_controls_payload() -> str:
    reviewed = load_spec(ROOT / "examples/procurement-review.yaml")
    runtime_review = decide_action(
        reviewed,
        origin_agent="procurement",
        capability="supplier.bank_account.write",
    )
    lease = issue_approval_lease(
        reviewed,
        runtime_review,
        approved_by="alice@example.com",
        approver_group="procurement-security",
        secret=DEMO_SECRET,
        now=DEMO_TIME,
        lease_id="CF-APR-DEMO0001",
        context={"pr": 284, "ticket": "SEC-91"},
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        runtime_authorized = authorize_action(
            reviewed,
            origin_agent="procurement",
            capability="supplier.bank_account.write",
            approval_lease=lease,
            approval_secret=DEMO_SECRET,
            usage_path=Path(temp_dir) / "approval-usage.json",
            now=DEMO_TIME + timedelta(minutes=1),
        )

    base = load_spec(ROOT / "examples/procurement-base.yaml")
    candidate = load_spec(ROOT / "examples/procurement-candidate.yaml")
    impact = build_impact_report(base, candidate, use_llm=False)
    policy = build_policy_plan(impact)
    payload = {
        "runtime_review": runtime_review,
        "approval_lease": {
            **{key: value for key, value in lease.items() if key != "signature"},
            "signature_present": True,
            "demo_only": True,
        },
        "runtime_authorized": runtime_authorized,
        "policy_plan": policy,
        "probe": {
            "status": "LOCAL_MODEL_REQUIRED",
            "engine": "Ollama",
            "primary_command": "changefence impact ... --llm --promptfoo-out changefence-tests.yaml",
            "claim": "Change-directed hypotheses are generated locally and remain HYPOTHESIZED until an external harness runs them."
        },
        "ledger": {
            "status": "AVAILABLE",
            "format": "hash-chained JSONL",
            "commands": ["changefence ledger-append", "changefence ledger-verify"],
            "claim": "Impact, approval issuance, and runtime consumption can be recorded in a tamper-evident local evidence chain."
        }
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail if committed demo data differs from engine output")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    expected_files = {
        **{f"{slug}.json": _impact_payload(slug, config) for slug, config in SCENARIOS.items()},
        "suite-controls.json": _suite_controls_payload(),
    }
    drift = []
    for filename, expected in expected_files.items():
        path = OUT / filename
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
