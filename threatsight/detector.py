"""
Credential-stuffing detector  (MITRE ATT&CK T1110.004).

Idea (behaviour, not a single IP blocklist): for each source IP, look at
1-minute windows of login attempts and flag a window when ONE ip produces a
burst of FAILED logins (401) -- the fingerprint of someone spraying stolen
credentials. We also note if the client looks scripted (not a real browser),
which raises confidence.

Run from the project root:
    python -m log2sigma.detect
"""

from __future__ import annotations

import polars as pl

from .parse import LogEvent, parse_file

# --- tunable thresholds (this is the "detection logic" you'd defend in interview) ---
WINDOW = "1m"          # group attempts into 1-minute buckets
MIN_FAILURES = 20      # this many 401s from one IP in one window = suspicious


def detect_credential_stuffing(events: list[LogEvent]) -> list[dict]:
    """Return one detection dict per (ip, window) that looks like credential stuffing."""
    if not events:
        return []

    df = pl.DataFrame(
        {
            "ip": [e.ip for e in events],
            "timestamp": [e.timestamp for e in events],
            "status": [e.status for e in events],
            "path": [e.path for e in events],
            "user_agent": [e.user_agent for e in events],
        }
    )

    windowed = (
        df.filter(pl.col("path") == "/login")
        # bucket each attempt into its 1-minute window
        .with_columns(pl.col("timestamp").dt.truncate(WINDOW).alias("window_start"))
        # per IP, per minute: how many failed? how many total? all non-browser?
        .group_by(["ip", "window_start"])
        .agg(
            failed=(pl.col("status") == 401).sum(),
            total=pl.len(),
            scripted=(~pl.col("user_agent").str.contains("Mozilla")).all(),
        )
        .with_columns((pl.col("failed") / pl.col("total")).alias("failure_ratio"))
        # the actual rule: a burst of failures from one IP in one minute
        .filter(pl.col("failed") >= MIN_FAILURES)
        .sort("failed", descending=True)
    )

    detections = []
    for row in windowed.iter_rows(named=True):
        # confidence: more failures + high failure ratio + scripted client = more sure
        confidence = 0.6 + 0.3 * row["failure_ratio"] + (0.1 if row["scripted"] else 0.0)
        detections.append(
            {
                "technique": "T1110.004",
                "ip": row["ip"],
                "window_start": row["window_start"],
                "failed": row["failed"],
                "total": row["total"],
                "failure_ratio": round(row["failure_ratio"], 2),
                "scripted_ua": row["scripted"],
                "confidence": round(min(confidence, 0.99), 2),
            }
        )
    return detections


def main() -> None:
    events = parse_file("data/sample/access.log")
    hits = detect_credential_stuffing(events)
    print(f"Analysed {len(events)} events -> {len(hits)} detection(s):\n")
    for h in hits:
        print(
            f"  [{h['technique']}] {h['ip']}  "
            f"{h['failed']}/{h['total']} failed logins in 1 min "
            f"(ratio {h['failure_ratio']}, scripted={h['scripted_ua']}) "
            f"-> confidence {h['confidence']}"
        )


if __name__ == "__main__":
    main()