"""
Multi-agent SOC investigation.

Three collaborating agents turn raw detections into a final, justified assessment:

  1. Triage agent        - assigns each detection a disposition (likely-threat /
                           needs-investigation / likely-benign) and a priority
  2. Investigation agent - a Claude tool-use loop that pivots on the prioritised
                           IPs (events, reputation, ATT&CK) and summarises
  3. Justification agent - writes the final incident assessment + reasoning

Context management: tools return small summaries, never raw log lines. The
investigation loop is bounded by max_steps.

Needs ANTHROPIC_API_KEY (and THREATSIGHT_INSECURE_SSL=1 if your network
intercepts HTTPS).

Run from the project root:
    python -m threatsight.orchestrator data/sample/access.log
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from pydantic import BaseModel

from .ai_analyze import DEFAULT_MODEL, _make_client
from .anomaly import detect_anomalies
from .attack import get_technique
from .detector import detect_signatures
from .parse import parse_file

MAX_STEPS = 6


def _collect_detections(events) -> list[dict]:
    sigs = detect_signatures(events)
    sig_ips = {d["ip"] for d in sigs}
    anom = [a for a in detect_anomalies(events) if a["ip"] not in sig_ips]
    return sigs + anom


def _tools_for(events):
    """Tools the investigation agent can call. Each returns a SMALL summary."""

    def run_signature_detectors(**_):
        return detect_signatures(events)

    def run_anomaly_detection(**_):
        return detect_anomalies(events)

    def get_events_for_ip(ip):
        hits = [e for e in events if e.ip == ip]
        return {"ip": ip, "count": len(hits),
                "sample": [{"time": str(e.timestamp), "method": e.method, "path": e.path,
                            "status": e.status, "ua": e.user_agent} for e in hits[:8]]}

    def lookup_attack_technique(technique_id):
        return get_technique(technique_id)

    def check_ip_reputation(ip):
        return {"ip": ip, "malicious": ip.startswith(("45.", "185.", "91.")), "source": "stub"}

    def search_attack_knowledge(query):
        from .rag import retrieve  # RAG over the ATT&CK knowledge base
        return retrieve(query)

    return {
        "run_signature_detectors": run_signature_detectors,
        "run_anomaly_detection": run_anomaly_detection,
        "get_events_for_ip": get_events_for_ip,
        "lookup_attack_technique": lookup_attack_technique,
        "check_ip_reputation": check_ip_reputation,
        "search_attack_knowledge": search_attack_knowledge,
    }


TOOL_SCHEMAS = [
    {"name": "run_signature_detectors", "description": "Signature detections.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "run_anomaly_detection", "description": "Anomalous source IPs.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "get_events_for_ip", "description": "Event sample for one IP (forensic pivot).",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}},
    {"name": "lookup_attack_technique", "description": "MITRE ATT&CK technique lookup.",
     "input_schema": {"type": "object", "properties": {"technique_id": {"type": "string"}}, "required": ["technique_id"]}},
    {"name": "check_ip_reputation", "description": "Is an IP known-malicious?",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}},
    {"name": "search_attack_knowledge",
     "description": "RAG: retrieve relevant MITRE ATT&CK technique knowledge for a free-text query.",
     "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}},
]


def _text(resp) -> str:
    return "".join(getattr(b, "text", "") for b in resp.content if getattr(b, "type", None) == "text")


# --- Agent 1: Triage ---
class TriageItem(BaseModel):
    ip: str
    disposition: str  # likely-threat | needs-investigation | likely-benign
    priority: int     # 1 = highest
    reason: str


class Triage(BaseModel):
    items: list[TriageItem]


def triage_agent(client, model, detections) -> Triage:
    tool = {"name": "report_triage", "description": "Report the triage.",
            "input_schema": Triage.model_json_schema()}
    resp = client.messages.create(
        model=model, max_tokens=800,
        system="You are a SOC triage agent. For each detection, assign a disposition "
               "(likely-threat / needs-investigation / likely-benign), a priority (1=highest), "
               "and a one-line reason. Use the report_triage tool.",
        tools=[tool], tool_choice={"type": "tool", "name": "report_triage"},
        messages=[{"role": "user", "content": "Detections:\n" + json.dumps(detections, default=str)}],
    )
    for b in resp.content:
        if getattr(b, "type", None) == "tool_use":
            return Triage.model_validate(b.input)
    return Triage(items=[])


# --- Agent 2: Investigation (tool-use loop) ---
def investigation_agent(client, model, events, focus_ips, max_steps=MAX_STEPS) -> str:
    tools = _tools_for(events)
    messages = [{"role": "user", "content":
                 f"Investigate these prioritised sources: {', '.join(focus_ips) or 'all detections'}. "
                 "Use the tools to pivot, then summarise what each did and how severe."}]
    for _ in range(max_steps):
        resp = client.messages.create(model=model, max_tokens=1200,
            system="You are a SOC investigation agent. Pivot on events, check reputation, and use "
                   "search_attack_knowledge to retrieve relevant ATT&CK context (RAG), then "
                   "summarise what each source did and how severe. Do not ask the user questions.",
            tools=TOOL_SCHEMAS, messages=messages)
        messages.append({"role": "assistant", "content": resp.content})
        tool_uses = [b for b in resp.content if getattr(b, "type", None) == "tool_use"]
        if not tool_uses:
            return _text(resp)
        results = []
        for tu in tool_uses:
            try:
                out = tools[tu.name](**tu.input)
            except Exception as e:
                out = {"error": str(e)}
            results.append({"type": "tool_result", "tool_use_id": tu.id,
                            "content": json.dumps(out, default=str)})
        messages.append({"role": "user", "content": results})
    return "Investigation reached max steps."


# --- Agent 3: Justification ---
def justification_agent(client, model, triage, investigation) -> str:
    resp = client.messages.create(
        model=model, max_tokens=800,
        system="You are a SOC lead. From the triage and the investigation findings, write a "
               "concise final incident assessment: who, what, severity, recommended actions, "
               "with brief justification.",
        messages=[{"role": "user", "content":
                   f"Triage:\n{json.dumps(triage, default=str)}\n\nInvestigation findings:\n{investigation}"}],
    )
    return _text(resp)


def investigate(log_path, model: str = DEFAULT_MODEL, max_steps: int = MAX_STEPS, client=None) -> dict:
    """Run the 3-agent pipeline: triage -> investigation -> justification."""
    events = parse_file(log_path)
    detections = _collect_detections(events)
    client = client or _make_client()

    triage = triage_agent(client, model, detections)
    focus = [i.ip for i in triage.items if i.disposition != "likely-benign"]
    investigation = investigation_agent(client, model, events, focus, max_steps)
    assessment = justification_agent(client, model, triage.model_dump(), investigation)

    return {"triage": triage.model_dump()["items"], "investigation": investigation, "assessment": assessment}


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/sample/access.log")
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("Set ANTHROPIC_API_KEY first.")
        return
    res = investigate(path)
    print("== Triage ==")
    for i in res["triage"]:
        print(f"  [P{i['priority']}] {i['ip']} — {i['disposition']}: {i['reason']}")
    print("\n== Investigation ==\n" + res["investigation"])
    print("\n== Assessment ==\n" + res["assessment"])


if __name__ == "__main__":
    main()