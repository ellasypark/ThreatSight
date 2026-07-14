"""
Threat report generator.

Combines both detection layers into one report:
  - Signature detections (known TTPs)  -> from detector.detect_signatures
  - Behavioral anomalies (unknown)     -> from anomaly.detect_anomalies

Technique metadata is pulled from the official ATT&CK STIX dataset
(attack.get_technique) -- no hardcoded technique names.

Run from the project root:
    python -m threatsight.report
Writes: reports/triage-report.md
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..detection.anomaly import detect_anomalies
from ..enrichment.attack import get_technique
from ..detection.detector import detect_signatures
from ..ingest.parse import parse_file

OUTPUT = Path("reports/triage-report.md")

REASON_TEXT = {
    "requests": "unusually high request volume",
    "not_found_ratio": "high 404 rate",
    "distinct_paths": "probing many distinct paths",
    "error_ratio": "high error rate",
}


def render(sigs: list[dict], anom: list[dict], source: str, n: int) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    L = [
        "# Detection Triage Report",
        "",
        f"- Generated: {now}",
        f"- Source: `{source}`",
        f"- Events analysed: {n}",
        f"- Signature detections: {len(sigs)}  |  Behavioral anomalies: {len(anom)}",
        "",
        "---",
        "",
        "## Signature detections (known TTPs)",
        "",
    ]
    if not sigs:
        L.append("_None._")
    for d in sigs:
        info = get_technique(d["technique"])
        L += [
            f"### [{d['severity']}] {info['name']} — {d['ip']}",
            f"- **ATT&CK:** [{d['technique']} {info['name']}]({info['url']}) (Tactic: {info['tactic']})",
            f"- **Evidence:** {d['summary']}",
            f"- **Confidence:** {d['confidence']}",
            f"- **Action:** {d['action']}",
            "",
        ]

    L += ["---", "", "## Behavioral anomalies (unknown / no signature)", ""]
    if not anom:
        L.append("_None._")
    for d in anom:
        info = get_technique(d["technique"])
        why = ", ".join(REASON_TEXT.get(r, r) for r in d["reasons"])
        L += [
            f"### [P3] Anomalous source — {d['ip']}",
            f"- **Why flagged:** {why}",
            f"- **Behaviour:** {d['requests']} requests, {d['distinct_paths']} distinct paths, "
            f"404 ratio {d['not_found_ratio']}, scripted: {d['scripted_ua']}",
            f"- **Candidate ATT&CK:** [{d['technique']} {info['name']}]({info['url']}) "
            f"(Tactic: {info['tactic']}) — *candidate, needs analyst review*",
            f"- **Confidence:** {d['confidence']}",
            f"- **Action:** investigate {d['ip']}; no known signature matched — possible novel/recon activity",
            "",
        ]
    return "\n".join(L)


def main() -> None:
    source = "data/sample/access.log"
    events = parse_file(source)

    sigs = detect_signatures(events)
    sig_ips = {d["ip"] for d in sigs}
    anom = [a for a in detect_anomalies(events) if a["ip"] not in sig_ips]

    report = render(sigs, anom, source, len(events))
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(report, encoding="utf-8")
    print(f"Wrote report: {len(sigs)} signature + {len(anom)} anomaly detection(s)\n")
    print(report)


if __name__ == "__main__":
    main()