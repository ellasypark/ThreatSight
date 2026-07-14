"""
Detection metrics — precision, recall, false-positive rate on a labelled set.

Builds a synthetic labelled log (we KNOW which IPs are attacks vs normal), runs
the detectors, and reports the numbers. This is the difference between "I built
a thing" and "I built a thing I measured and trust".

NOTE: the labelled set is synthetic and clean, so the numbers are high. On
noisy real-world traffic they would be lower — swap in a public WAF dataset to
measure that.

Run:  python -m threatsight.metrics
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from ..detection.anomaly import detect_anomalies
from ..detection.detector import detect_signatures
from ..ingest.parse import parse_line

BROWSER = "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0"


def _line(ip, when, method, path, status, ua):
    ts = when.strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} 232 "-" "{ua}"'


def build_labelled(n_normal: int = 50):
    """A labelled log: normal users (benign) + 3 known attackers (malicious)."""
    random.seed(7)
    base = datetime(2026, 1, 1, 2, 0, 0, tzinfo=timezone.utc)
    lines, t = [], base
    normal = [f"10.0.{i // 256}.{i % 256}" for i in range(n_normal)]
    for ip in normal:  # browsing + occasional benign 401 typo
        for _ in range(random.randint(4, 9)):
            t += timedelta(seconds=3)
            if random.random() < 0.08:
                lines.append(_line(ip, t, "POST", "/login", 401, BROWSER))
            else:
                lines.append(_line(ip, t, "GET", "/home", 200, BROWSER))

    cred = "45.143.220.81"; t = base + timedelta(minutes=30)
    for _ in range(30):
        t += timedelta(milliseconds=300)
        lines.append(_line(cred, t, "POST", "/login", 401, "python-requests/2.31.0"))

    sqli = "91.92.240.10"; t = base + timedelta(minutes=40)
    for _ in range(12):
        t += timedelta(seconds=1)
        lines.append(_line(sqli, t, "GET", "/x?q=1'OR'1'='1", 200, "sqlmap/1.7"))

    scan = "185.220.101.5"; t = base + timedelta(minutes=50)
    for p in [f"/{c}{c}" for c in "abcdefghijklmnopqrstuvwx"]:
        t += timedelta(milliseconds=300)
        lines.append(_line(scan, t, "GET", p, 404, "curl/8.4.0"))

    events = [parse_line(x) for x in lines]
    return events, set(normal), {cred, sqli}, {scan}


def _prf(flagged, positives, negatives) -> dict:
    tp = len(flagged & positives)
    fp = len(flagged & negatives)
    fn = len(positives - flagged)
    tn = len(negatives - flagged)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 3), "recall": round(recall, 3),
            "fp_rate": round(fp_rate, 3)}


def compute() -> dict:
    events, benign, mal_sig, mal_anom = build_labelled()
    sig = {d["ip"] for d in detect_signatures(events)}
    anom = {a["ip"] for a in detect_anomalies(events)}
    return {
        "n_ips": len(benign | mal_sig | mal_anom),
        "signature": _prf(sig, mal_sig, benign),
        "anomaly": _prf(anom, mal_anom, benign),
        "overall": _prf(sig | anom, mal_sig | mal_anom, benign),
    }


def main() -> None:
    r = compute()
    print(f"Detection metrics (synthetic labelled set, {r['n_ips']} source IPs)\n")
    print(f"{'detector':<12}{'precision':<11}{'recall':<9}{'FP rate'}")
    for k in ("signature", "anomaly", "overall"):
        m = r[k]
        print(f"{k:<12}{m['precision']:<11}{m['recall']:<9}{m['fp_rate']}")


if __name__ == "__main__":
    main()

# ── evaluation against a semi-synthetic corpus (real base + injected attacks) ──
def evaluate_corpus(log_path="data/corpus/access.log",
                    labels_path="data/corpus/labels.json") -> dict:
    """Score the detectors against a corpus produced by `threatsight corpus`.

    Unlike compute(), the negatives here are REAL/realistic benign traffic —
    crawlers, monitors, login typos — so FP rate is meaningful and usually > 0.
    Reports overall PRF plus how many false positives were 'borderline' (the
    crawler/monitor traps), which is the number the WAF-tuning work must drive down.
    """
    import json
    from pathlib import Path

    from ..ingest.parse import parse_file

    labels = json.loads(Path(labels_path).read_text(encoding="utf-8"))
    positives = set(labels["malicious"])
    benign = set(labels["benign_ips"])
    borderline = set(labels["borderline_ips"])
    negatives = benign | borderline

    events = parse_file(log_path)
    sig = {d["ip"] for d in detect_signatures(events)}
    anom = {a["ip"] for a in detect_anomalies(events)}
    flagged = sig | anom

    fp_ips = flagged & negatives
    result = {
        "n_events": len(events),
        "n_positives": len(positives),
        "n_negatives": len(negatives),
        "signature": _prf(sig, positives, negatives),
        "anomaly": _prf(anom, positives, negatives),
        "overall": _prf(flagged, positives, negatives),
        "false_positives": sorted(fp_ips),
        "fp_from_borderline": sorted(fp_ips & borderline),
        "missed_attacks": {ip: labels["malicious"][ip]["attack"]
                           for ip in sorted(positives - flagged)},
    }
    return result


def main_corpus() -> None:
    r = evaluate_corpus()
    print(f"Corpus metrics — {r['n_events']} events, "
          f"{r['n_positives']} attackers vs {r['n_negatives']} benign IPs\n")
    print(f"{'detector':<12}{'precision':<11}{'recall':<9}{'FP rate'}")
    for k in ("signature", "anomaly", "overall"):
        m = r[k]
        print(f"{k:<12}{m['precision']:<11}{m['recall']:<9}{m['fp_rate']}")
    if r["false_positives"]:
        print(f"\nfalse positives ({len(r['false_positives'])}): {r['false_positives']}")
        if r["fp_from_borderline"]:
            print(f"  ...of which crawler/monitor traps: {r['fp_from_borderline']}")
    if r["missed_attacks"]:
        print(f"\nmissed attacks: {r['missed_attacks']}")


if __name__ == "__main__":
    main()