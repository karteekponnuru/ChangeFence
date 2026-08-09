from pathlib import Path
from changefence.behavior import compare_behavior
from changefence.engine import compare
from changefence.report import render_html
from changefence.spec import load_spec

ROOT = Path(__file__).resolve().parents[1]


def test_html_report_contains_core_finding():
    structural = compare(load_spec(ROOT / "examples" / "procurement-base.yaml"), load_spec(ROOT / "examples" / "procurement-candidate.yaml"))
    behavior = compare_behavior(ROOT / "examples" / "behavior-base.json", ROOT / "examples" / "behavior-candidate.json")
    html = render_html(structural, behavior)
    assert "ChangeFence" in html
    assert "FIN-001" in html
    assert "INDIRECT-PROMPT-INJECTION" in html
