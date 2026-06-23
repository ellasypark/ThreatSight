"""
Adversary emulation + detection validation (purple team).

  Red    — generate discrete attack scenarios, INCLUDING an evasive variant.
  Blue   — run the detectors against each.
  Purple — print a coverage matrix: what was caught, by which layer, and where
           the gaps are, mapped to MITRE ATT&CK.

This is "think like an adversary, then prove the defense": it shows the fast
attack is caught, the *low-and-slow* attack EVADES the signature rule but is
still caught by the anomaly layer (defense in depth), and a benign user is NOT
flagged.

Run from the project root:
    python -m threatsight.emulate
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .anomaly import detect_anomalies
from .detector import detect_credential_stuffing
from .parse import parse_line

BASE = datetime(2026, 1, 1, 2, 0, 0, tzinfo=timezone.utc)
BROWSER = "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0"
NORMAL_IPS = [f"10.0.0.{n}" for n in range(1, 21)]
ODD_PATHS = [
    "/admin", "/.env", "/wp-login.php", "/db", "/config.php", "/backup.zip",
    "/.git/config", "/shell.php", "/old", "/test", "/api/v1/users", "/phpmyadmin",
    "/server-status", "/.aws/credentials", "/secret", "/cgi-bin", "/vendor",
    "/.ssh/id_rsa", "/wp-admin", "/console",
]


def _line(ip, when, method, path, status, ua):
    ts = when.strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} 232 "-" "{ua}"'


def _baseline():
    """Realistic normal traffic to compare against (incl. a few benign login typos)."""
    lines, t = [], BASE
    for k, ip in enumerate(NORMAL_IPS):
        for p in ["/home", "/products"]:
            t += timedelta(seconds=5)
            lines.append(_line(ip, t, "GET", p, 200, BROWSER))
        t += timedelta(seconds=5)
        lines.append(_line(ip, t, "POST", "/login", 401 if k % 7 == 0 else 200, BROWSER))
    return lines


def _cred_fast():
    """Loud credential stuffing: 30 failed logins in seconds (signature should catch)."""
    ip, lines, t = "45.143.220.81", [], BASE + timedelta(minutes=20)
    for _ in range(30):
        t += timedelta(milliseconds=300)
        lines.append(_line(ip, t, "POST", "/login", 401, "python-requests/2.31.0"))
    return ip, lines


def _cred_slow():
    """Evasive: 18 fails over ~27 min, staying under the 20/min signature threshold."""
    ip, lines, t = "45.143.220.82", [], BASE + timedelta(minutes=20)
    for _ in range(18):
        t += timedelta(seconds=90)
        lines.append(_line(ip, t, "POST", "/login", 401, "python-requests/2.31.0"))
    return ip, lines


def _scanner():
    """Recon: probes many odd paths -> 404 (no signature; anomaly should catch)."""
    ip, lines, t = "185.220.101.5", [], BASE + timedelta(minutes=20)
    for p in ODD_PATHS:
        t += timedelta(milliseconds=300)
        lines.append(_line(ip, t, "GET", p, 404, "curl/8.4.0"))
    return ip, lines


def _benign_control():
    """A real user mistyping their password — must NOT be flagged (false-positive check)."""
    ip, lines, t = "10.0.0.99", [], BASE + timedelta(minutes=20)
    for i in range(4):
        t += timedelta(seconds=30)
        lines.append(_line(ip, t, "POST", "/login", 401 if i < 3 else 200, BROWSER))
    return ip, lines


SCENARIOS = [
    ("Credential stuffing (fast)",       "T1110.004", _cred_fast,      True),
    ("Credential stuffing (low & slow)", "T1110.004", _cred_slow,      True),
    ("Path scanning / recon",            "T1595.002", _scanner,        True),
    ("Benign login typos (control)",     "-",         _benign_control, False),
]


def run():
    baseline = _baseline()
    rows = []
    for name, tech, build, is_attack in SCENARIOS:
        ip, attack = build()
        events = [parse_line(line) for line in baseline + attack]
        by_sig = ip in {d["ip"] for d in detect_credential_stuffing(events)}
        by_anom = ip in {d["ip"] for d in detect_anomalies(events)}
        rows.append((name, tech, is_attack, by_sig, by_anom, by_sig or by_anom))
    return rows


def main() -> None:
    rows = run()
    print(f"{'Scenario':<34}{'ATT&CK':<12}{'Signature':<11}{'Anomaly':<9}Result")
    print("-" * 84)
    for name, tech, is_attack, by_sig, by_anom, detected in rows:
        sig = "caught" if by_sig else "-"
        anom = "caught" if by_anom else "-"
        if is_attack:
            result = "DETECTED" if detected else "MISSED (coverage gap)"
        else:
            result = "correctly ignored" if not detected else "FALSE POSITIVE"
        print(f"{name:<34}{tech:<12}{sig:<11}{anom:<9}{result}")


if __name__ == "__main__":
    main()