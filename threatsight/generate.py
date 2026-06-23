"""
Synthetic web-access log generator.

Produces normal traffic plus several attacks so we can demo every detector:
  1. NORMAL    - users browsing (GET) + occasional logins.
  2. CREDENTIAL STUFFING - one IP, burst of failed logins (signature: T1110.004).
  3. SCANNER   - one IP probing odd paths -> 404 (anomaly layer).
  4. SQL INJECTION - one IP sending SQLi payloads in the URL (signature: T1190).

Run from the project root:
    python -m threatsight.generate
Output: data/sample/access.log
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUTPUT = Path("data/sample/access.log")

NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0",
    "Mozilla/5.0 (iPhone) Safari/604.1",
    "Mozilla/5.0 (Macintosh) Firefox/127.0",
]
BOT_UA = "python-requests/2.31.0"   # credential stuffing
SCANNER_UA = "curl/8.4.0"           # scanner
SQLMAP_UA = "sqlmap/1.7"            # sql injection tool

NORMAL_IPS = [f"203.0.113.{n}" for n in range(2, 60)]
ATTACK_IP = "45.143.220.81"
SCANNER_IP = "185.220.101.5"
SQLI_IP = "91.92.240.10"

NORMAL_PATHS = ["/", "/home", "/products", "/cart", "/search", "/account"]
ODD_PATHS = [
    "/admin", "/wp-login.php", "/.env", "/phpmyadmin", "/api/v1/users", "/config.php",
    "/backup.zip", "/.git/config", "/server-status", "/shell.php", "/old", "/test",
    "/db", "/.aws/credentials",
]
# URL payloads (no raw spaces; /**/ is a real WAF-evasion trick)
SQLI_PAYLOADS = [
    "/search?q=1'OR'1'='1",
    "/item?id=1'OR'1'='1--",
    "/news?id=1)UNION/**/SELECT/**/pass/**/FROM/**/users",
    "/p?id=1'OR'1'='1",
    "/cat?c=1'AND'1'='1",
]


def fmt(ip, when, method, path, status, ua):
    ts = when.strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} 232 "-" "{ua}"'


def main() -> None:
    random.seed(42)
    base = datetime(2026, 6, 15, 2, 0, 0, tzinfo=timezone.utc)
    events: list[tuple[datetime, str]] = []

    # 1) normal users
    t = base
    for _ in range(220):
        t += timedelta(seconds=random.randint(3, 20))
        ip, ua = random.choice(NORMAL_IPS), random.choice(NORMAL_USER_AGENTS)
        if random.random() < 0.2:
            status = 200 if random.random() > 0.05 else 401
            events.append((t, fmt(ip, t, "POST", "/login", status, ua)))
        else:
            events.append((t, fmt(ip, t, "GET", random.choice(NORMAL_PATHS), 200, ua)))

    # 2) credential stuffing
    t = base + timedelta(hours=1)
    for i in range(150):
        t += timedelta(milliseconds=random.randint(50, 400))
        events.append((t, fmt(ATTACK_IP, t, "POST", "/login", 200 if i == 149 else 401, BOT_UA)))

    # 3) scanner
    t = base + timedelta(hours=1, minutes=30)
    for _ in range(90):
        t += timedelta(milliseconds=random.randint(100, 600))
        events.append((t, fmt(SCANNER_IP, t, "GET", random.choice(ODD_PATHS), 404, SCANNER_UA)))

    # 4) sql injection
    t = base + timedelta(hours=2)
    for _ in range(12):
        t += timedelta(milliseconds=random.randint(200, 800))
        events.append((t, fmt(SQLI_IP, t, "GET", random.choice(SQLI_PAYLOADS), 200, SQLMAP_UA)))

    events.sort(key=lambda e: e[0])
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(line for _, line in events) + "\n", encoding="utf-8")
    print(f"Wrote {len(events)} log lines (normal + credential stuffing + scanner + sqli)")


if __name__ == "__main__":
    main()