"""
Self-contained HTML dashboard generator.

Reads a log, runs the detectors, and writes a single dashboard.html (charts via
Chart.js CDN). Open it in a browser -- no server / Elasticsearch / Docker needed.

Run from the project root:
    python -m threatsight.dashboard data/sample/access.log
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from .anomaly import detect_anomalies
from .attack import get_technique
from .detector import detect_signatures
from .parse import parse_file

OUTPUT = Path("dashboard.html")
SEV_COLOR = {"P1": "#E24B4A", "P2": "#EF9F27", "P3": "#378ADD", "INFO": "#888780"}


def build_stats(log_path) -> dict:
    events = parse_file(log_path)
    sigs = detect_signatures(events)
    sig_ips = {d["ip"] for d in sigs}
    anoms = [a for a in detect_anomalies(events) if a["ip"] not in sig_ips]

    dets = []
    for d in sigs:
        dets.append({**d, "name": get_technique(d["technique"])["name"], "layer": "signature"})
    for a in anoms:
        dets.append({**a, "name": get_technique(a["technique"])["name"],
                     "layer": "anomaly", "severity": a.get("severity", "P3")})
    dets.sort(key=lambda d: d["confidence"], reverse=True)

    sev = Counter(d["severity"] for d in dets)
    return {
        "events": len(events),
        "detections": len(dets),
        "p1": sev.get("P1", 0),
        "attacker_ips": len({d["ip"] for d in dets}),
        "techniques": len({d["technique"] for d in dets}),
        "severity": dict(sev),
        "by_technique": dict(Counter(d["name"] for d in dets)),
        "by_layer": dict(Counter(d["layer"] for d in dets)),
        "timeline": dict(sorted(Counter(e.timestamp.strftime("%H:00") for e in events).items())),
        "feed": [{"severity": d["severity"], "name": d["name"], "ip": d["ip"],
                  "technique": d["technique"], "confidence": d["confidence"]} for d in dets],
    }


def render_html(stats: dict) -> str:
    cards = [
        ("Events analysed", stats["events"], ""),
        ("Detections", stats["detections"], ""),
        ("Critical (P1)", stats["p1"], "#E24B4A"),
        ("Attacker IPs", stats["attacker_ips"], ""),
        ("ATT&CK techniques", stats["techniques"], ""),
    ]
    card_html = "".join(
        f'<div class="card"><div class="lbl">{l}</div>'
        f'<div class="num" style="{("color:"+c) if c else ""}">{v}</div></div>'
        for l, v, c in cards
    )
    feed_html = "".join(
        f'<div class="row"><span class="sev s{f["severity"]}">{f["severity"]}</span>'
        f'<span class="nm">{f["name"]}</span><span class="ip">{f["ip"]}</span>'
        f'<span class="meta">{f["technique"]} &middot; conf {f["confidence"]}</span></div>'
        for f in stats["feed"]
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>ThreatSight Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
body{{font-family:system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#1b1b1a;background:#faf9f5}}
h1{{font-size:22px;font-weight:600;margin-bottom:2px}} .sub{{color:#6b6a64;margin-bottom:20px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}}
.card{{background:#fff;border:1px solid #e7e5dd;border-radius:12px;padding:16px}}
.lbl{{font-size:13px;color:#6b6a64}} .num{{font-size:26px;font-weight:600;margin-top:4px}}
.panels{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}}
.panel{{background:#fff;border:1px solid #e7e5dd;border-radius:12px;padding:16px;margin-bottom:24px}}
.panel h2{{font-size:14px;font-weight:600;margin:0 0 12px;color:#444}}
.wide{{grid-column:1/-1}}
.row{{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid #e7e5dd;border-radius:8px;margin-bottom:8px}}
.sev{{font-size:12px;font-weight:600;padding:2px 8px;border-radius:6px}}
.sP1{{background:#FCEBEB;color:#791F1F}} .sP2{{background:#FAEEDA;color:#633806}} .sP3{{background:#E6F1FB;color:#0C447C}} .sINFO{{background:#F1EFE8;color:#444441}}
.nm{{font-weight:600}} .ip{{font-family:monospace;color:#6b6a64;font-size:13px}} .meta{{margin-left:auto;font-size:12px;color:#6b6a64}}
canvas{{max-height:220px}}
</style></head><body>
<h1>ThreatSight Dashboard</h1>
<div class="sub">WAF/web-log threat analysis &middot; signature + anomaly &middot; mapped to MITRE ATT&CK</div>
<div class="grid">{card_html}</div>
<div class="panel wide"><h2>Activity timeline (events per hour)</h2><canvas id="tl"></canvas></div>
<div class="panels">
  <div class="panel" style="margin:0"><h2>Severity</h2><canvas id="sev"></canvas></div>
  <div class="panel" style="margin:0"><h2>Detection layer</h2><canvas id="lay"></canvas></div>
</div>
<div class="panel wide"><h2>Detections by technique</h2><canvas id="tech"></canvas></div>
<div class="panel wide"><h2>Recent detections</h2>{feed_html}</div>
<script>
const D={json.dumps(stats)};
const SEV={json.dumps(SEV_COLOR)};
new Chart(tl,{{type:'line',data:{{labels:Object.keys(D.timeline),datasets:[{{data:Object.values(D.timeline),borderColor:'#378ADD',backgroundColor:'rgba(55,138,221,.15)',fill:true,tension:.3}}]}},options:{{plugins:{{legend:{{display:false}}}},scales:{{y:{{beginAtZero:true}}}}}}}});
new Chart(sev,{{type:'doughnut',data:{{labels:Object.keys(D.severity),datasets:[{{data:Object.values(D.severity),backgroundColor:Object.keys(D.severity).map(s=>SEV[s]||'#888'),borderWidth:0}}]}},options:{{cutout:'60%'}}}});
new Chart(lay,{{type:'doughnut',data:{{labels:Object.keys(D.by_layer),datasets:[{{data:Object.values(D.by_layer),backgroundColor:['#534AB7','#1D9E75'],borderWidth:0}}]}},options:{{cutout:'60%'}}}});
new Chart(tech,{{type:'bar',data:{{labels:Object.keys(D.by_technique),datasets:[{{data:Object.values(D.by_technique),backgroundColor:'#534AB7'}}]}},options:{{plugins:{{legend:{{display:false}}}},scales:{{y:{{beginAtZero:true,ticks:{{precision:0}}}}}}}}}});
</script></body></html>"""


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/sample/access.log")
    stats = build_stats(path)
    OUTPUT.write_text(render_html(stats), encoding="utf-8")
    print(f"Wrote {OUTPUT} ({stats['detections']} detections from {stats['events']} events). "
          f"Open it in a browser.")


if __name__ == "__main__":
    main()