from fastapi.testclient import TestClient

from changefence.webapp import app


client = TestClient(app)


def example_payload():
    response = client.get("/api/example")
    assert response.status_code == 200
    return response.json()


def test_playground_health():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_playground_analysis_uses_external_policy_ground_truth():
    example = example_payload()
    response = client.post(
        "/api/analyze",
        json={
            "baseline": example["baseline"],
            "candidate": example["candidate"],
            "policy": example["policy"],
            "fail_on": "high",
        },
    )
    assert response.status_code == 200
    result = response.json()
    assert result["decision"] == "BLOCK"
    assert result["violations"][0]["id"] == "FIN-001"
    assert result["policy_authority"]["name"] == "ACME Agent Security Policy"
    assert "payment.execute" in [item["capability"] for item in result["new_capabilities"]]
    assert result["graph"]["nodes"]
    assert result["graph"]["edges"]


def test_playground_runtime_returns_review_and_block():
    example = example_payload()
    review = client.post(
        "/api/runtime",
        json={
            "spec": example["candidate"],
            "policy": example["policy"],
            "origin_agent": "procurement",
            "capability": "supplier.bank_account.write",
        },
    )
    assert review.status_code == 200
    assert review.json()["decision"] == "REVIEW"
    assert review.json()["review"]["rule_id"] == "REV-001"

    blocked = client.post(
        "/api/runtime",
        json={
            "spec": example["candidate"],
            "policy": example["policy"],
            "origin_agent": "procurement",
            "executor_agent": "finance",
            "capability": "payment.execute",
        },
    )
    assert blocked.status_code == 200
    assert blocked.json()["decision"] == "BLOCK"
    assert blocked.json()["invariant"]["id"] == "FIN-001"


def test_playground_rejects_policy_that_contains_agent_architecture():
    example = example_payload()
    bad_policy = example["policy"] + "\nagents:\n  procurement: {}\n"
    response = client.post(
        "/api/analyze",
        json={
            "baseline": example["baseline"],
            "candidate": example["candidate"],
            "policy": bad_policy,
        },
    )
    assert response.status_code == 400
    assert "security policy only" in response.json()["detail"]
