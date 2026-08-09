from pathlib import Path

import pytest

from changefence.impact import build_impact_report
from changefence.runtime import decide_action
from changefence.spec import SpecError, load_spec

POLICY = "examples/acme-security-policy.yaml"
BASE = "examples/procurement-agents-base.yaml"
CANDIDATE = "examples/procurement-agents-candidate.yaml"


def test_external_policy_is_authoritative_for_impact():
    base = load_spec(BASE, policy_path=POLICY)
    candidate = load_spec(CANDIDATE, policy_path=POLICY)
    report = build_impact_report(base, candidate)

    assert report["decision"] == "BLOCK"
    assert report["structural"]["gate_violations"][0]["id"] == "FIN-001"
    assert report["policy_authority"]["name"] == "ACME Agent Security Policy"
    assert report["policy_authority"]["version"] == "3.2"
    assert len(report["policy_authority"]["digest"]) == 64


def test_external_policy_drives_runtime_review():
    spec = load_spec(BASE, policy_path=POLICY)
    decision = decide_action(
        spec,
        origin_agent="procurement",
        capability="supplier.bank_account.write",
    )

    assert decision["decision"] == "REVIEW"
    assert decision["review"]["rule_id"] == "REV-001"
    assert decision["review"]["approver"] == "procurement-security"
    assert decision["policy_authority"]["owner"] == "Enterprise Security"


def test_developer_embedded_rules_cannot_replace_external_policy(tmp_path):
    # Simulates a developer attempting to ship their own harmless-looking policy
    # alongside the risky delegation. --policy must ignore these embedded rules.
    agent = tmp_path / "candidate.yaml"
    agent.write_text(
        Path(CANDIDATE).read_text(encoding="utf-8")
        + "\ninvariants: []\nreviews: []\n",
        encoding="utf-8",
    )

    spec = load_spec(agent, policy_path=POLICY)
    blocked = decide_action(
        spec,
        origin_agent="procurement",
        executor_agent="finance",
        capability="payment.execute",
    )

    assert blocked["decision"] == "BLOCK"
    assert blocked["invariant"]["id"] == "FIN-001"
    assert spec.policy_authority.name == "ACME Agent Security Policy"


def test_policy_registry_rejects_agent_architecture(tmp_path):
    bad_policy = tmp_path / "bad-policy.yaml"
    bad_policy.write_text(
        """policy:\n  name: Bad Policy\n  version: '1'\n  owner: Security\nagents:\n  procurement: {}\n""",
        encoding="utf-8",
    )

    with pytest.raises(SpecError, match="security policy only"):
        load_spec(BASE, policy_path=bad_policy)
