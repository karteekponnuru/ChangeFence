from pathlib import Path
import pytest
from changefence.engine import analyze, compare
from changefence.spec import SpecError, load_spec

ROOT = Path(__file__).resolve().parents[1]


def test_detects_transitive_authority_regression():
    report = compare(load_spec(ROOT / "examples" / "procurement-base.yaml"), load_spec(ROOT / "examples" / "procurement-candidate.yaml"))
    assert report["status"] == "FAIL"
    assert report["summary"]["new_security_regressions"] == 1
    violation = report["new_security_regressions"][0]
    assert violation["id"] == "FIN-001"
    assert violation["capability"] == "payment.execute"


def test_safe_candidate_passes():
    report = compare(load_spec(ROOT / "examples" / "procurement-base.yaml"), load_spec(ROOT / "examples" / "procurement-safe-candidate.yaml"))
    assert report["status"] == "PASS"
    assert report["summary"]["new_security_regressions"] == 0


def test_change_metadata_detected():
    report = compare(load_spec(ROOT / "examples" / "procurement-base.yaml"), load_spec(ROOT / "examples" / "procurement-candidate.yaml"))
    types = {x["type"] for x in report["structural_diff"]["changes"]}
    assert "prompt_changed" in types
    assert "delegation_added" in types


def test_cycles_do_not_loop_forever(tmp_path):
    p = tmp_path / "cycle.yaml"
    p.write_text("""system: cycle
agents:
  a: {delegates_to: [b]}
  b: {delegates_to: [a], tools: [t]}
tools:
  t: {capabilities: [x]}
invariants: []
""")
    result = analyze(load_spec(p))
    assert any(x.source_agent == "a" and x.capability == "x" for x in result.reachable)


def test_unknown_tool_is_rejected(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("""system: bad
agents:
  a: {tools: [missing]}
tools: {}
invariants: []
""")
    with pytest.raises(SpecError):
        load_spec(p)
