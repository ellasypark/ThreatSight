"""
ThreatSight web server (FastAPI) — the web dashboard.

Self-contained: it computes the dashboard stats itself (build_stats) and serves
the web frontend. No Elasticsearch / Kibana / Docker — just `uvicorn`.

Run from the project root:
    uvicorn threatsight.server:app --reload
Then open http://127.0.0.1:8000
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from ..detection.anomaly import detect_anomalies
from ..enrichment.attack import get_technique
from ..detection.detector import detect_signatures
from ..evaluation.metrics import compute as compute_metrics
from ..enrichment.owasp import owasp_for
from ..ingest.parse import parse_file
from ..enrichment.threat_model import coverage as threat_coverage
from ..enrichment.threat_model import summary as threat_summary

app = FastAPI(title="ThreatSight")
FRONTEND = Path(__file__).parent / "frontend" / "index.html"


def build_stats(log_path) -> dict:
    """Run the analysis and return everything the dashboard needs."""
    events = parse_file(log_path)
    sigs = detect_signatures(events)
    sig_ips = {d["ip"] for d in sigs}
    anom = [a for a in detect_anomalies(events) if a["ip"] not in sig_ips]

    dets = []
    for d in sigs + anom:
        info = get_technique(d["technique"])
        dets.append({
            "ip": d["ip"],
            "technique": d["technique"],
            "name": info["name"],
            "severity": d.get("severity", "P3"),
            "confidence": d["confidence"],
            "tactic": info["tactic"],
            "owasp": owasp_for(d["technique"]),
            "description": info["description"],
            "data_sources": info["data_sources"],
            "mitigations": info["mitigations"],
            "layer": "signature" if d in sigs else "anomaly",
        })
    dets.sort(key=lambda d: d["confidence"], reverse=True)

    sev = Counter(d["severity"] for d in dets)
    tm = threat_coverage({d["technique"] for d in dets})
    return {
        "events": len(events),
        "detections": len(dets),
        "p1": sev.get("P1", 0),
        "attacker_ips": len({d["ip"] for d in dets}),
        "techniques": len({d["technique"] for d in dets}),
        "severity": dict(sev),
        "by_layer": dict(Counter(d["layer"] for d in dets)),
        "threat_model": tm,
        "threat_summary": threat_summary(tm),
        "metrics": compute_metrics(),
        "timeline": dict(sorted(Counter(e.timestamp.strftime("%H:00") for e in events).items())),
        "feed": dets,
    }


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return FRONTEND.read_text(encoding="utf-8")


@app.get("/api/analyze")
def analyze(log: str = "data/sample/access.log"):
    path = Path(log)
    if not path.exists():
        return JSONResponse({"error": f"log not found: {log}"}, status_code=404)
    return build_stats(path)