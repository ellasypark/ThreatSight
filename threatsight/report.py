"""
ATT&CK-mapped triage report generator.

Turns detections into a human-readable report (ATT&CK technique + tactic,
severity, what happened, recommended actions) so triage is instant and
consistent. Technique metadata is pulled from the official ATT&CK STIX dataset
via attack.get_technique() -- no hardcoded technique names.

Run from the project root:
    python -m threatsight.report
Writes: reports/triage-report.md
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .attack import get_technique
from .detector import detect_credential_stuffing
from .parse import parse_file

OUTPUT = Path("reports/triage-report.md")


def severity(detection: dict) -> str:
    """P1 if an account was actually taken over, else P2 (attack in progress)."""
    successes = detection["total"] - detection["failed"]
    return "P1" if successes > 0 else "P2"


def recommended_actions(detection: dict) -> list[str]:
    successes = detection["total"] - detection["failed"]
    actions: list[str] = []
    if successes > 0:
        actions.append(
            f"Force password reset + kill sessions for any account that "
            f"returned 200 from {detection['ip']} (account compromise suspected)"
        )
    actions.append(f"Block / rate-limit source IP {detection['ip']}")
    actions.append("Check IP reputation (known proxy / scanner / bad ASN)")
    return actions


def render(detections: list[dict], source: str, n_events: int) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Detection Triage Report",
        "",
        f"- Generated: {now}",
        f"- Source: `{source}`",
        f"- Events analysed: {n_events}",
        f"- Detections: {len(detections)}",
        "",
        "---",
        "",
    ]
    if not detections:
        lines.append("_No detections._")
        return "\n".join(lines)

    for d in detections:
        info = get_technique(d["technique"])  # pulled from ATT&CK STIX dataset
        successes = d["total"] - d["failed"]
        lines += [
            f"## [{severity(d)}] {info['name']} — {d['ip']}",
            "",
            f"- **ATT&CK:** [{d['technique']} {info['name']}]({info['url']}) "
            f"(Tactic: {info['tactic']})",
            f"- **Window:** {d['window_start']:%Y-%m-%d %H:%M UTC} (1 min)",
            f"- **Activity:** {d['failed']} failed / {d['total']} total logins "
            f"(failure ratio {d['failure_ratio']}), scripted client: {d['scripted_ua']}",
            f"- **Outcome:** {successes} successful login(s) during the burst"
            + (" → **account compromise suspected**" if successes else " (no success yet)"),
            f"- **Confidence:** {d['confidence']}",
            "",
            "### Recommended actions",
        ]
        for i, a in enumerate(recommended_actions(d), 1):
            lines.append(f"{i}. {a}")
        lines += ["", "---", ""]
    return "\n".join(lines)


def main() -> None:
    source = "data/sample/access.log"
    events = parse_file(source)
    detections = detect_credential_stuffing(events)
    report = render(detections, source, len(events))
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(report, encoding="utf-8")
    print(f"Wrote triage report ({len(detections)} detection(s)) to {OUTPUT}\n")
    print(report)


if __name__ == "__main__":
    main()