import json

from changefence.impact import build_impact_report
from changefence.ledger import append_event, verify_ledger
from changefence.policy import build_policy_plan
from changefence.runtime import decide_action
from changefence.spec import load_spec


def test_runtime_blocks_explicit_invariant_and_allows_known_safe_action():
    baseline = load_spec("examples/procurement-base.yaml")
    candidate = load_spec("examples/procurement-candidate.yaml")

    allowed = decide_action(baseline, origin_agent="procurement", capability="supplier.read")
    blocked = decide_action(
        candidate,
        origin_agent="procurement",
        executor_agent="finance",
        capability="payment.execute",
    )

    assert allowed["decision"] == "ALLOW"
    assert allowed["path"]
    assert blocked["decision"] == "BLOCK"
    assert blocked["invariant"]["id"] == "FIN-001"


def test_runtime_reviews_unmodeled_capability():
    baseline = load_spec("examples/procurement-base.yaml")
    decision = decide_action(baseline, origin_agent="procurement", capability="root.shell")
    assert decision["decision"] == "REVIEW"
    assert decision["evidence_level"] == "UNKNOWN"


def test_policy_plan_comes_from_proven_gate_violation():
    base = load_spec("examples/procurement-base.yaml")
    candidate = load_spec("examples/procurement-candidate.yaml")
    impact = build_impact_report(base, candidate)
    plan = build_policy_plan(impact)

    assert plan["summary"]["recommendations"] == 1
    recommendation = plan["recommendations"][0]
    assert recommendation["causal_origin"] == "procurement"
    assert recommendation["capability"] == "payment.execute"
    assert recommendation["auto_deploy"] is False


def test_ledger_detects_tampering(tmp_path):
    ledger = tmp_path / "security-ledger.jsonl"
    append_event(
        ledger,
        event_type="impact",
        payload={"decision": "BLOCK", "capability": "payment.execute"},
        timestamp="2026-08-09T00:00:00+00:00",
    )
    append_event(
        ledger,
        event_type="runtime",
        payload={"decision": "BLOCK", "origin_agent": "procurement"},
        timestamp="2026-08-09T00:01:00+00:00",
    )
    assert verify_ledger(ledger)["valid"] is True

    lines = ledger.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["payload"]["decision"] = "ALLOW"
    lines[0] = json.dumps(first, sort_keys=True)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert verify_ledger(ledger)["valid"] is False
