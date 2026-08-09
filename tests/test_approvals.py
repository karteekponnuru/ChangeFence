import json
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

import pytest

from changefence.approvals import ApprovalLeaseError, issue_approval_lease, validate_approval_lease
from changefence.models import Agent
from changefence.runtime import authorize_action, decide_action
from changefence.spec import load_spec

SECRET = "test-secret-that-is-definitely-longer-than-32-bytes"
NOW = datetime(2026, 8, 9, 22, 30, tzinfo=timezone.utc)


def reviewed():
    spec = load_spec("examples/procurement-review.yaml")
    decision = decide_action(
        spec,
        origin_agent="procurement",
        capability="supplier.bank_account.write",
    )
    return spec, decision


def lease(spec, decision, **kwargs):
    return issue_approval_lease(
        spec,
        decision,
        approved_by=kwargs.pop("approved_by", "alice@example.com"),
        approver_group=kwargs.pop("approver_group", "procurement-security"),
        secret=SECRET,
        now=kwargs.pop("now", NOW),
        lease_id=kwargs.pop("lease_id", "CF-APR-TEST0001"),
        context=kwargs.pop("context", {"pr": 284}),
        **kwargs,
    )


def test_valid_lease_allows_once_and_replay_is_reviewed(tmp_path):
    spec, decision = reviewed()
    token = lease(spec, decision)
    usage = tmp_path / "usage.json"

    first = authorize_action(
        spec,
        origin_agent="procurement",
        capability="supplier.bank_account.write",
        approval_lease=token,
        approval_secret=SECRET,
        usage_path=usage,
        now=NOW + timedelta(minutes=1),
    )
    assert first["decision"] == "ALLOW"
    assert first["authorization"]["type"] == "APPROVAL_LEASE"
    assert first["authorization"]["approved_by"] == "alice@example.com"
    assert first["authorization"]["uses_remaining"] == 0

    replay = authorize_action(
        spec,
        origin_agent="procurement",
        capability="supplier.bank_account.write",
        approval_lease=token,
        approval_secret=SECRET,
        usage_path=usage,
        now=NOW + timedelta(minutes=2),
    )
    assert replay["decision"] == "REVIEW"
    assert "exhausted" in replay["lease_validation"]["reason"]


def test_expired_lease_does_not_authorize(tmp_path):
    spec, decision = reviewed()
    token = lease(spec, decision)
    result = authorize_action(
        spec,
        origin_agent="procurement",
        capability="supplier.bank_account.write",
        approval_lease=token,
        approval_secret=SECRET,
        usage_path=tmp_path / "usage.json",
        now=NOW + timedelta(minutes=16),
    )
    assert result["decision"] == "REVIEW"
    assert "expired" in result["lease_validation"]["reason"]


def test_tampered_lease_does_not_authorize(tmp_path):
    spec, decision = reviewed()
    token = lease(spec, decision)
    token["capability"] = "payment.execute"
    result = authorize_action(
        spec,
        origin_agent="procurement",
        capability="supplier.bank_account.write",
        approval_lease=token,
        approval_secret=SECRET,
        usage_path=tmp_path / "usage.json",
        now=NOW + timedelta(minutes=1),
    )
    assert result["decision"] == "REVIEW"
    assert "signature" in result["lease_validation"]["reason"]


def test_hard_invariant_cannot_be_overridden_by_lease(tmp_path):
    spec, decision = reviewed()
    token = lease(spec, decision)
    result = authorize_action(
        spec,
        origin_agent="procurement",
        executor_agent="finance",
        capability="payment.execute",
        approval_lease=token,
        approval_secret=SECRET,
        usage_path=tmp_path / "usage.json",
        now=NOW + timedelta(minutes=1),
    )
    assert result["decision"] == "BLOCK"
    assert result["invariant"]["id"] == "FIN-001"


def test_unknown_authority_cannot_get_lease():
    spec = load_spec("examples/procurement-review.yaml")
    decision = decide_action(spec, origin_agent="procurement", capability="root.shell")
    with pytest.raises(ApprovalLeaseError, match="Default/unknown"):
        issue_approval_lease(
            spec,
            decision,
            approved_by="alice@example.com",
            approver_group="security",
            secret=SECRET,
            now=NOW,
        )


def test_wrong_approver_group_cannot_issue_lease():
    spec, decision = reviewed()
    with pytest.raises(ApprovalLeaseError, match="requires approver group"):
        lease(spec, decision, approver_group="developers")


def test_usage_store_tampering_fails_closed(tmp_path):
    spec, decision = reviewed()
    token = lease(spec, decision)
    usage = tmp_path / "usage.json"
    first = authorize_action(
        spec,
        origin_agent="procurement",
        capability="supplier.bank_account.write",
        approval_lease=token,
        approval_secret=SECRET,
        usage_path=usage,
        now=NOW + timedelta(minutes=1),
    )
    assert first["decision"] == "ALLOW"

    data = json.loads(usage.read_text())
    data["leases"][token["lease_id"]]["uses"] = 0
    usage.write_text(json.dumps(data))
    result = validate_approval_lease(
        spec,
        decision,
        token,
        secret=SECRET,
        usage_path=usage,
        now=NOW + timedelta(minutes=2),
    )
    assert result["valid"] is False
    assert "usage store signature" in result["reason"]


def test_lease_is_bound_to_exact_authority_path(tmp_path):
    spec, decision = reviewed()
    token = lease(spec, decision)

    spec.agents["helper"] = Agent(name="helper", tools=["supplier"])
    spec.agents["procurement"].tools = []
    spec.agents["procurement"].delegates_to = ["helper"]

    result = authorize_action(
        spec,
        origin_agent="procurement",
        capability="supplier.bank_account.write",
        approval_lease=token,
        approval_secret=SECRET,
        usage_path=tmp_path / "usage.json",
        now=NOW + timedelta(minutes=1),
    )
    assert result["decision"] == "REVIEW"
    assert "authority_path_hash" in result["lease_validation"]["reason"]


def test_concurrent_one_use_lease_allows_only_one_caller(tmp_path):
    spec, decision = reviewed()
    token = lease(spec, decision)
    usage = tmp_path / "usage.json"

    def call_runtime(_):
        return authorize_action(
            spec,
            origin_agent="procurement",
            capability="supplier.bank_account.write",
            approval_lease=token,
            approval_secret=SECRET,
            usage_path=usage,
            now=NOW + timedelta(minutes=1),
        )["decision"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        decisions = list(pool.map(call_runtime, range(2)))
    assert sorted(decisions) == ["ALLOW", "REVIEW"]
