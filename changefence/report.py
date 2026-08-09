from html import escape
from pathlib import Path


def _path_text(path):
    return " → ".join(escape(str(x)) for x in path)


def render_html(structural: dict, behavior: dict | None = None) -> str:
    status = "FAIL" if structural["status"] == "FAIL" or (behavior and behavior["status"] == "FAIL") else "PASS"
    status_class = "bad" if status == "FAIL" else "good"

    regressions = "".join(
        f"<article class='finding'><div class='sev'>{escape(v['severity'].upper())}</div>"
        f"<h3>{escape(v['id'])}: {escape(v['description'])}</h3>"
        f"<p><strong>New authority:</strong> {escape(v['source_agent'])} → {escape(v['capability'])}</p>"
        f"<p class='path'>{_path_text(v['path'])}</p></article>"
        for v in structural["new_security_regressions"]
    ) or "<p class='muted'>No new invariant violations.</p>"

    caps = "".join(
        f"<tr><td>{escape(x['source_agent'])}</td><td>{escape(x['capability'])}</td>"
        f"<td><span class='pill {escape(x['severity'])}'>{escape(x['severity'])}</span></td>"
        f"<td>{_path_text(x['path'])}</td></tr>"
        for x in structural["new_capabilities"]
    ) or "<tr><td colspan='4' class='muted'>No new reachable capabilities.</td></tr>"

    behavior_html = ""
    if behavior:
        rows = "".join(
            f"<tr><td>{escape(x['scenario'])}</td><td>{x['base']['pass_rate']:.0%}</td>"
            f"<td>{x['candidate']['pass_rate']:.0%}</td>"
            f"<td class={'badtext' if x['regression'] else 'goodtext' if x['improvement'] else ''}>{x['pass_rate_delta']:+.0%}</td></tr>"
            for x in behavior["scenarios"]
        )
        behavior_html = f"""
        <section><h2>Behavioral security diff</h2>
        <p>Identical adversarial scenarios were run against the baseline and candidate. A negative delta means the candidate passed fewer trials.</p>
        <div class='table-wrap'><table><thead><tr><th>Scenario</th><th>Baseline pass</th><th>Candidate pass</th><th>Change</th></tr></thead><tbody>{rows}</tbody></table></div>
        </section>"""

    return f"""<!doctype html>
<html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>ChangeFence Security Diff</title>
<style>
:root{{--bg:#07111f;--panel:#0d1a2b;--line:#1d3148;--text:#ecf3fb;--muted:#99abc0;--cyan:#54d2ff;--bad:#ff6577;--good:#52d6a3;}}
*{{box-sizing:border-box}}body{{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;background:linear-gradient(160deg,#07111f,#0a1422 55%,#07111f);color:var(--text)}}
main{{max-width:1100px;margin:auto;padding:48px 24px 80px}}.brand{{font-weight:800;letter-spacing:.12em;color:var(--cyan)}}h1{{font-size:clamp(36px,7vw,72px);line-height:1;margin:16px 0}}h2{{margin-top:0}}p{{line-height:1.65}}.muted{{color:var(--muted)}}
.hero{{padding:28px 0 38px}}.status{{display:inline-block;padding:8px 12px;border-radius:999px;font-weight:800}}.status.bad{{background:#3a1520;color:#ff93a0}}.status.good{{background:#0c382d;color:#72e7bd}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0 36px}}.metric,section,.finding{{background:rgba(13,26,43,.92);border:1px solid var(--line);border-radius:18px}}.metric{{padding:18px}}.metric b{{font-size:28px;display:block}}section{{padding:24px;margin:18px 0}}.finding{{padding:18px;margin:12px 0}}.sev{{font-size:12px;font-weight:800;color:var(--bad);letter-spacing:.1em}}.path{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#b9c8d7;background:#08111d;padding:12px;border-radius:10px;overflow:auto}}
.table-wrap{{overflow:auto}}table{{width:100%;border-collapse:collapse}}th,td{{padding:12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}}.pill{{padding:4px 8px;border-radius:999px;font-size:12px}}.pill.critical,.pill.high{{background:#3a1520;color:#ff93a0}}.pill.medium{{background:#382f10;color:#ffd870}}.pill.low{{background:#10372f;color:#79e3c0}}.badtext{{color:var(--bad);font-weight:800}}.goodtext{{color:var(--good);font-weight:800}}
footer{{color:var(--muted);padding-top:28px}}@media(max-width:760px){{.grid{{grid-template-columns:repeat(2,1fr)}}}}
</style></head><body><main>
<div class='hero'><div class='brand'>CHANGEFENCE</div><h1>Agent security diff</h1><p class='muted'>Your code diff is not your agent diff. ChangeFence shows what security-relevant authority and behavior changed between releases.</p><span class='status {status_class}'>{status}</span></div>
<div class='grid'>
<div class='metric'><span class='muted'>Structural changes</span><b>{structural['summary']['structural_changes']}</b></div>
<div class='metric'><span class='muted'>New capabilities</span><b>{structural['summary']['new_capabilities']}</b></div>
<div class='metric'><span class='muted'>New regressions</span><b>{structural['summary']['new_security_regressions']}</b></div>
<div class='metric'><span class='muted'>Gate violations</span><b>{structural['summary']['gate_violations']}</b></div>
</div>
<section><h2>New security regressions</h2>{regressions}</section>
<section><h2>New capability surface</h2><div class='table-wrap'><table><thead><tr><th>Agent</th><th>Capability</th><th>Risk</th><th>Path</th></tr></thead><tbody>{caps}</tbody></table></div></section>
{behavior_html}
<footer>Generated by ChangeFence · Security change control for AI agents</footer>
</main></body></html>"""


def write_html(path: str | Path, structural: dict, behavior: dict | None = None) -> Path:
    path = Path(path)
    path.write_text(render_html(structural, behavior), encoding="utf-8")
    return path
