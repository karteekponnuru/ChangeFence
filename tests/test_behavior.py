from pathlib import Path
from changefence.behavior import compare_behavior

ROOT = Path(__file__).resolve().parents[1]


def test_behavior_regressions_are_detected():
    report = compare_behavior(ROOT / "examples" / "behavior-base.json", ROOT / "examples" / "behavior-candidate.json")
    assert report["status"] == "FAIL"
    names = {x["scenario"] for x in report["regressions"]}
    assert "INDIRECT-PROMPT-INJECTION" in names
    assert "TOOL-AUTHORITY-ESCALATION" in names
    assert "SENSITIVE-DATA-EXFILTRATION" not in names
