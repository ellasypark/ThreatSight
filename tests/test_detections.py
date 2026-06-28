"""
Tests for ThreatSight detections.

We build a small, fully-labelled log (we KNOW which IPs are attacks vs normal),
run the detectors, and assert they catch the attacks WITHOUT flagging normal
users. This proves low false positives -- and re-runs on every push via CI.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from threatsight.anomaly import detect_anomalies
from threatsight.detector import detect_credential_stuffing, detect_sqli
from threatsight.parse import parse_line

BASE = datetime(2026, 1, 1, 3, 0, 0, tzinfo=timezone.utc)
NORMAL_IPS = [f"10.0.0.{n}" for n in range(1, 21)]
ATTACKER = "45.143.220.81"   # credential stuffing
SCANNER = "185.220.101.5"    # path scanner (anomaly)
SQLI_IP = "91.92.240.10"     # sql injection
BROWSER = "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0"
ODD = [
    "/a", "/.env", "/wp-login.php", "/db", "/config.php", "/backup.zip", "/.git/config",
    "/shell.php", "/old", "/t", "/api/v1/users", "/phpmyadmin", "/server-status",
    "/.aws/credentials", "/secret", "/cgi-bin", "/vendor", "/.ssh/id_rsa", "/wp-admin",
    "/console", "/debug", "/api/keys", "/staging", "/internal", "/manager",
]
SQLI = ["/search?q=1'OR'1'='1", "/item?id=1)UNION/**/SELECT/**/x", "/p?id=1'OR'1'='1"]


def _line(ip, when, method, path, status, ua):
    ts = when.strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} 232 "-" "{ua}"'


def build_events():
    lines, t = [], BASE
    for ip in NORMAL_IPS:
        for p in ["/home", "/products"]:
            t += timedelta(seconds=7)
            lines.append(_line(ip, t, "GET", p, 200, BROWSER))
        t += timedelta(seconds=7)
        lines.append(_line(ip, t, "POST", "/login", 200, BROWSER))
    t = BASE + timedelta(minutes=30)
    for _ in range(30):
        t += timedelta(milliseconds=300)
        lines.append(_line(ATTACKER, t, "POST", "/login", 401, "python-requests/2.31.0"))
    t = BASE + timedelta(minutes=45)
    for p in ODD:
        t += timedelta(milliseconds=300)
        lines.append(_line(SCANNER, t, "GET", p, 404, "curl/8.4.0"))
    t = BASE + timedelta(minutes=50)
    for i in range(8):
        t += timedelta(seconds=2)
        lines.append(_line(SQLI_IP, t, "GET", SQLI[i % 3], 200, "sqlmap/1.7"))
    return [parse_line(line) for line in lines]


EVENTS = build_events()


def test_signature_catches_credential_stuffing():
    assert ATTACKER in {d["ip"] for d in detect_credential_stuffing(EVENTS)}


def test_signature_no_false_positive_on_normal():
    assert {d["ip"] for d in detect_credential_stuffing(EVENTS)}.isdisjoint(NORMAL_IPS)


def test_sqli_is_detected():
    assert SQLI_IP in {d["ip"] for d in detect_sqli(EVENTS)}


def test_sqli_no_false_positive_on_normal():
    assert {d["ip"] for d in detect_sqli(EVENTS)}.isdisjoint(NORMAL_IPS)


def test_anomaly_catches_scanner():
    assert SCANNER in {d["ip"] for d in detect_anomalies(EVENTS)}


def test_anomaly_no_false_positive_on_normal():
    assert {d["ip"] for d in detect_anomalies(EVENTS)}.isdisjoint(NORMAL_IPS)