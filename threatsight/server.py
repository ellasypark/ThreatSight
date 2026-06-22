"""
ThreatSight web server (FastAPI).

A lightweight self-hosted dashboard: runs the analysis on demand and serves a
web frontend that visualises it. No Elasticsearch / Kibana / Docker -- just
`uvicorn`. Each user runs their own instance (or you run it locally to demo).

Run from the project root:
    uvicorn threatsight.server:app --reload
Then open http://127.0.0.1:8000
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from .dashboard import build_stats

app = FastAPI(title="ThreatSight")
FRONTEND = Path(__file__).parent / "frontend" / "index.html"


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    """Serve the dashboard web page."""
    return FRONTEND.read_text(encoding="utf-8")


@app.get("/api/analyze")
def analyze(log: str = "data/sample/access.log"):
    """Run the analysis on a log file and return the dashboard stats as JSON."""
    path = Path(log)
    if not path.exists():
        return JSONResponse({"error": f"log not found: {log}"}, status_code=404)
    return build_stats(path)