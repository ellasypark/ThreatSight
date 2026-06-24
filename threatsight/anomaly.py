"""
Behavioral anomaly detection (Layer 2: catches UNKNOWN attacks).

Signature detectors only catch attacks we defined in advance. This layer needs
no signature: it builds a per-source-IP behavioural profile, then flags IPs that
are statistical outliers vs the rest of the traffic -- surfacing novel or recon
activity (e.g. a scanner) that no rule was written for.

Method: robust z-score (median + MAD) per feature. An IP is anomalous if any
feature is >= Z_THRESHOLD robust std-devs from normal. We report WHICH features
were extreme (explainable) and a *candidate* ATT&CK technique for analyst review.

MIN_REQUESTS guard: IPs with very little activity are skipped -- there isn't
enough behaviour to judge them, and flagging them causes false positives (this
guard was added after adversary emulation showed a benign user with a few login
typos getting flagged).

Run from the project root:
    python -m threatsight.anomaly
"""

from __future__ import annotations

import numpy as np
import polars as pl

from .config import ANOMALY_MIN_REQUESTS, ANOMALY_Z_THRESHOLD
from .parse import parse_file

Z_THRESHOLD = ANOMALY_Z_THRESHOLD    # tunable in config.py
MIN_REQUESTS = ANOMALY_MIN_REQUESTS
FEATURES = ["requests", "not_found_ratio", "distinct_paths", "error_ratio"]


def _robust_z(x: np.ndarray) -> np.ndarray:
    """Median/MAD-based z-score: robust to outliers, unlike mean/std."""
    median = np.median(x)
    mad = np.median(np.abs(x - median))
    if mad > 0:
        return 0.6745 * (x - median) / mad
    sd = x.std()
    return (x - x.mean()) / sd if sd > 0 else np.zeros_like(x)


def _candidate_technique(reasons: list[str]) -> str:
    """Best-guess ATT&CK technique from the dominant anomaly signal (for triage)."""
    if "distinct_paths" in reasons or "not_found_ratio" in reasons:
        return "T1595.002"  # Active Scanning: Vulnerability Scanning
    if "requests" in reasons:
        return "T1499"  # Endpoint Denial of Service
    return "T1595"  # Active Scanning


def detect_anomalies(events) -> list[dict]:
    """Flag source IPs whose behaviour is a statistical outlier vs the rest."""
    if not events:
        return []

    df = pl.DataFrame(
        {
            "ip": [e.ip for e in events],
            "status": [e.status for e in events],
            "path": [e.path for e in events],
            "user_agent": [e.user_agent for e in events],
        }
    )

    feats = (
        df.group_by("ip")
        .agg(
            requests=pl.len(),
            not_found=(pl.col("status") == 404).sum(),
            errors=(pl.col("status") >= 400).sum(),
            distinct_paths=pl.col("path").n_unique(),
            scripted=(~pl.col("user_agent").str.contains("Mozilla")).all(),
        )
        .with_columns(
            not_found_ratio=pl.col("not_found") / pl.col("requests"),
            error_ratio=pl.col("errors") / pl.col("requests"),
        )
    )
    if feats.height < 3:  # need a population to compare against
        return []

    z = {f: _robust_z(feats[f].to_numpy().astype(float)) for f in FEATURES}

    out = []
    for i, row in enumerate(feats.iter_rows(named=True)):
        if row["requests"] < MIN_REQUESTS:  # too little activity to judge
            continue
        reasons = [f for f in FEATURES if z[f][i] >= Z_THRESHOLD]
        if not reasons:
            continue
        max_z = max(z[f][i] for f in reasons)
        out.append(
            {
                "kind": "anomaly",
                "technique": _candidate_technique(reasons),
                "ip": row["ip"],
                "reasons": reasons,
                "requests": row["requests"],
                "distinct_paths": row["distinct_paths"],
                "not_found_ratio": round(row["not_found_ratio"], 2),
                "scripted_ua": row["scripted"],
                "confidence": round(min(0.95, 0.55 + 0.08 * (max_z - Z_THRESHOLD)), 2),
            }
        )
    return sorted(out, key=lambda d: d["confidence"], reverse=True)


def main() -> None:
    anomalies = detect_anomalies(parse_file("data/sample/access.log"))
    print(f"{len(anomalies)} anomaly finding(s):")
    for d in anomalies:
        print(f"  {d['ip']}  reasons={d['reasons']}  confidence={d['confidence']}")


if __name__ == "__main__":
    main()