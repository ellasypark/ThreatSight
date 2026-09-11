"""Portable, escaped HTML report. No network assets, scripts or server required."""
import html
import json


def render(result: dict) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    a = result["assessment"]
    rows = "".join("<tr><td>" + "</td><td>".join(esc(v) for v in (
        r["path"], r["current"]["waf_requests"], r["current"]["block_rate"],
        r["block_rate_change_pp"], r["current"]["app_5xx_rate"])) + "</td></tr>" for r in result["route_metrics"])
    claims = "".join(f'<li>{esc(c["text"])} <small>Evidence: {esc(", ".join(c["evidence_ids"]))}</small></li>' for c in a["claims"])
    missing = "".join(f"<li>{esc(v)}</li>" for v in a["missing_evidence"])
    steps = "".join(f"<li>{esc(v)}</li>" for v in a["next_steps"])
    evidence = "".join(f'<details><summary>{esc(k)}</summary><pre>{esc(json.dumps(v, indent=2))}</pre></details>' for k, v in result["evidence"].items())
    return f'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>ThreatSight · {esc(result['service'])}</title>
<style>body{{font:16px/1.6 system-ui,sans-serif;background:#f4f6fa;color:#18273c;margin:0}}main{{max-width:1000px;margin:40px auto;padding:24px}}section{{background:white;border:1px solid #dbe2eb;border-radius:12px;padding:24px;margin:20px 0}}h1{{font-size:36px}}h2{{font-size:22px}}small{{display:block;color:#52627a}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:12px;border-bottom:1px solid #eee}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}.scroll{{overflow-x:auto}}.badge{{color:#175859;font-weight:700}}details{{margin:12px 0}}</style>
<main><p class="badge">THREATSIGHT / LOCAL INCIDENT REPORT</p><h1>{esc(result['service'])}</h1>
<p>Attack, blocked legitimate traffic, or application failure?</p>
<section><h2>{esc(a['disposition'].replace('_',' ').capitalize())}</h2><ul>{claims}</ul>
<small>Mode: {esc(result['mode'])} · Model: {esc(result['model'] or 'none')} · {result['elapsed_seconds']:.3f}s · Paid API cost: $0; local compute cost unmeasured</small></section>
<section><h2>Service impact</h2><p>Rates are fractions (0–1); changes are percentage points. None means missing data. Blocked requests are not a count of confirmed attacks.</p><div class="scroll"><table><tr><th>Route</th><th>WAF requests</th><th>Block rate</th><th>Change (pp)</th><th>App 5xx rate</th></tr>{rows}</table></div></section>
<section><h2>Still needed</h2><ul>{missing}</ul><h2>Next checks</h2><ol>{steps}</ol></section>
<section><h2>Evidence</h2><p>Source content is untrusted. Existing citations do not guarantee a correct interpretation.</p>{evidence}</section>
<section><h2>Run details</h2><pre>{esc(json.dumps({k:v for k,v in result.items() if k not in ['evidence','route_metrics','assessment']},indent=2))}</pre></section></main></html>'''
