from changefence.semantic import analyze_semantic_change, build_inferred_specs, sanitize_semantic_output
from changefence.spec import load_spec


def test_semantic_output_fails_closed_on_unknown_entities():
    base = load_spec("examples/procurement-base.yaml")
    candidate = load_spec("examples/procurement-candidate.yaml")
    raw = {
        "capability_mappings": [
            {"tool":"payments","capability":"payment.refund","severity":"high","confidence":"high","applies_to":"both","evidence":"POST /refunds","rationale":"refund endpoint"},
            {"tool":"imaginary","capability":"root.shell","severity":"critical","confidence":"high","applies_to":"candidate","evidence":"made up","rationale":"hallucinated"},
            {"tool":"payments","capability":"NOT VALID","severity":"critical","confidence":"high","applies_to":"both","evidence":"bad name","rationale":"bad"},
        ],
        "semantic_risks": [
            {"id":"SEM-001","agent":"procurement","change_type":"prompt_constraint_weakened","affected_capability":"supplier.bank_account.write","severity":"high","confidence":"high","evidence":"- require approval / + update efficiently","rationale":"approval language weakened","recommended_verification":"attempt forged supplier update"},
            {"id":"SEM-002","agent":"ghost","change_type":"x","affected_capability":"payment.execute","severity":"critical","confidence":"high","evidence":"fake","rationale":"fake","recommended_verification":"fake"},
        ],
    }
    out = sanitize_semantic_output(base, candidate, raw)
    assert len(out["capability_mappings"]) == 1
    assert out["capability_mappings"][0]["evidence_level"] == "HYPOTHESIZED"
    assert len(out["semantic_risks"]) == 1
    assert out["semantic_risks"][0]["requires_runtime_verification"] is True


def test_semantic_analysis_accepts_injected_requester_and_preserves_provenance():
    base = load_spec("examples/procurement-base.yaml")
    candidate = load_spec("examples/procurement-candidate.yaml")
    def requester(**kwargs):
        assert "semantic change compiler" in kwargs["prompt"]
        return {
            "capability_mappings": [],
            "semantic_risks": [{"id":"SEM-001","agent":"procurement","change_type":"prompt_changed","affected_capability":"supplier.bank_account.write","severity":"high","confidence":"medium","evidence":"prompt_id changed from procurement-safe to procurement-with-finance-handoff","rationale":"approval behavior may differ","recommended_verification":"test supplier bank update without approval"}],
        }
    out = analyze_semantic_change(base, candidate, diff_text="- safe\n+ handoff", requester=requester)
    assert out["summary"]["semantic_risks"] == 1
    assert out["semantic_risks"][0]["evidence_level"] == "HYPOTHESIZED"


def test_high_confidence_mapping_builds_shadow_graph_only():
    base = load_spec("examples/procurement-base.yaml")
    candidate = load_spec("examples/procurement-candidate.yaml")
    mappings = [{"tool":"payments","capability":"payment.refund","severity":"high","confidence":"high","applies_to":"candidate","evidence":"POST /refund","rationale":"API operation","evidence_level":"HYPOTHESIZED"}]
    inferred_base, inferred_candidate, applied = build_inferred_specs(base, candidate, mappings)
    assert len(applied) == 1
    assert not any(c.name == "payment.refund" for c in candidate.tools["payments"].capabilities)
    assert any(c.name == "payment.refund" for c in inferred_candidate.tools["payments"].capabilities)
    assert not any(c.name == "payment.refund" for c in inferred_base.tools["payments"].capabilities)
