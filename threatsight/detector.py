"""
Signature detectors for known attack techniques (Layer 1).

Each detector returns dicts that share a common shape so the report can render
any of them the same way:
    technique, ip, severity, confidence, summary, action

detect_signatures() runs all of them. Adding a new technique = write one
function and add it to SIGNATURE_DETECTORS.
"""

from __future__ import annotations

import polars as pl

from .config import CRED_STUFFING_MIN_FAILURES, CRED_STUFFING_WINDOW
from .parse import parse_file

# --- credential stuffing (T1110.004) -------------------------------------------------
WINDOW = CRED_STUFFING_WINDOW          # tunable in config.py
MIN_FAILURES = CRED_STUFFING_MIN_FAILURES


def detect_credential_stuffing(events) -> list[dict]:
    if not events:
        return []
    df = pl.DataFrame({
        "ip": [e.ip for e in events], "timestamp": [e.timestamp for e in events],
        "status": [e.status for e in events], "path": [e.path for e in events],
        "user_agent": [e.user_agent for e in events],
    })
    w = (
        df.filter(pl.col("path") == "/login")
        .with_columns(pl.col("timestamp").dt.truncate(WINDOW).alias("window_start"))
        .group_by(["ip", "window_start"])
        .agg(
            failed=(pl.col("status") == 401).sum(),
            total=pl.len(),
            scripted=(~pl.col("user_agent").str.contains("Mozilla")).all(),
        )
        .with_columns((pl.col("failed") / pl.col("total")).alias("failure_ratio"))
        .filter(pl.col("failed") >= MIN_FAILURES)
        .sort("failed", descending=True)
    )
    out = []
    for r in w.iter_rows(named=True):
        ok = r["total"] - r["failed"]
        conf = 0.6 + 0.3 * r["failure_ratio"] + (0.1 if r["scripted"] else 0.0)
        summary = (
            f"{r['failed']} failed logins in 1 min (ratio {round(r['failure_ratio'], 2)}), "
            f"scripted={r['scripted']}"
            + (", 1+ success → account compromise suspected" if ok else "")
        )
        out.append({
            "technique": "T1110.004", "ip": r["ip"],
            "severity": "P1" if ok > 0 else "P2",
            "confidence": round(min(conf, 0.99), 2),
            "summary": summary,
            "action": f"Reset/kill sessions for accounts hit from {r['ip']}; block the IP",
        })
    return out


# --- SQL injection (T1190) -----------------------------------------------------------
# Strong, low-false-positive indicators (incl. /**/ WAF-evasion comments).
SQLI_PATTERN = (
    r"(?i)(union[/*\s]*select|'1'='1|or\s+1=1|information_schema"
    r"|xp_cmdshell|sleep\(\d|benchmark\(|drop\s+table|/\*\*/)"
)


def detect_sqli(events) -> list[dict]:
    if not events:
        return []
    df = pl.DataFrame({"ip": [e.ip for e in events], "path": [e.path for e in events]})
    hits = df.filter(pl.col("path").str.contains(SQLI_PATTERN))
    if hits.height == 0:
        return []
    grp = (
        hits.group_by("ip")
        .agg(count=pl.len(), sample=pl.col("path").first())
        .sort("count", descending=True)
    )
    out = []
    for r in grp.iter_rows(named=True):
        out.append({
            "technique": "T1190", "ip": r["ip"], "severity": "P2",
            "confidence": round(min(0.95, 0.7 + 0.05 * r["count"]), 2),
            "summary": f"{r['count']} SQL-injection payload(s) in request paths, e.g. {r['sample']}",
            "action": f"Block source IP {r['ip']}; review the targeted endpoint for injection",
        })
    return out


SIGNATURE_DETECTORS = [detect_credential_stuffing, detect_sqli]


def detect_signatures(events) -> list[dict]:
    """Run every signature detector and return the combined findings."""
    findings = []
    for detector in SIGNATURE_DETECTORS:
        findings.extend(detector(events))
    return findings


def main() -> None:
    findings = detect_signatures(parse_file("data/sample/access.log"))
    print(f"{len(findings)} signature detection(s):")
    for d in findings:
        print(f"  [{d['severity']}] {d['technique']} {d['ip']} (conf {d['confidence']}) - {d['summary']}")


if __name__ == "__main__":
    main()