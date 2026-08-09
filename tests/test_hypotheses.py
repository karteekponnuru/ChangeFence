from changefence.hypotheses import generate_attack_hypotheses, verify_hypotheses
from changefence.spec import load_spec


def test_verifies_new_and_unreachable_hypotheses():
    base = load_spec("examples/procurement-base.yaml")
    candidate = load_spec("examples/procurement-candidate.yaml")
    proposed = [
        {
            "id": "H-001",
            "title": "Delegated payment authority",
            "source_agent": "procurement",
            "target_capability": "payment.execute",
            "attacker_control": "supplier email",
            "rationale": "Procurement may delegate to Finance.",
            "proposed_path": ["procurement", "finance", "payment.execute"],
        },
        {
            "id": "H-002",
            "title": "Imagined capability",
            "source_agent": "procurement",
            "target_capability": "production.delete",
            "attacker_control": "supplier email",
            "rationale": "Model guessed a capability that is not reachable.",
            "proposed_path": ["procurement", "production.delete"],
        },
    ]

    verified = verify_hypotheses(base, candidate, proposed)
    assert verified[0]["verification"] == "VERIFIED_NEW"
    assert verified[0]["evidence_path"]
    assert verified[1]["verification"] == "UNREACHABLE"
    assert verified[1]["evidence_path"] == []


def test_generation_accepts_injected_local_requester():
    base = load_spec("examples/procurement-base.yaml")
    candidate = load_spec("examples/procurement-candidate.yaml")

    def fake_requester(**kwargs):
        assert kwargs["model"] == "gemma3"
        return [{
            "id": "H-001",
            "title": "Delegated payment authority",
            "source_agent": "procurement",
            "target_capability": "payment.execute",
            "attacker_control": "supplier email",
            "rationale": "Candidate delegation may expose payment execution.",
            "proposed_path": ["procurement", "finance", "payment.execute"],
        }]

    report = generate_attack_hypotheses(base, candidate, requester=fake_requester)
    assert report["summary"]["verified_new"] == 1
    assert report["hypotheses"][0]["verification"] == "VERIFIED_NEW"
