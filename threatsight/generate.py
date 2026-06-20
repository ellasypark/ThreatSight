"""
Synthetic web-access log generator.

Produces THREE kinds of traffic so we can demo both detection layers:

  1. NORMAL    - many users browsing (GET) + occasional logins.
  2. CREDENTIAL STUFFING - one IP, burst of failed logins (caught by the SIGNATURE layer).
  3. SCANNER   - one IP probing many odd paths -> 404s. No signature exists for this;
                 it's here to prove the ANOMALY layer catches unknown/recon activity.

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
BOT_UA = "python-requests/2.31.0"   # credential-stuffing client
SCANNER_UA = "curl/8.4.0"           # scanner client

NORMAL_IPS = [f"203.0.113.{n}" for n in range(2, 60)]
ATTACK_IP = "45.143.220.81"         # credential stuffing
SCANNER_IP = "185.220.101.5"        # scanner

NORMAL_PATHS = ["/", "/home", "/products", "/cart", "/search", "/account"]
ODD_PATHS = [
    "/admin", "/wp-login.php", "/.env", "/phpmyadmin", "/api/v1/users",
    "/config.php", "/backup.zip", "/.git/config", "/server-status",
    "/shell.php", "/old", "/test", "/db", "/.aws/credentials",
]


def fmt(ip: str, when: datetime, method: str, path: str, status: int, ua: str) -> str:
    ts = when.strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} 232 "-" "{ua}"'


def main() -> None:
    random.seed(42)
    base = datetime(2026, 6, 15, 2, 0, 0, tzinfo=timezone.utc)
    events: list[tuple[datetime, str]] = []

    # 1) normal users: mostly browsing, sometimes logging in
    t = base
    for _ in range(220):
        t += timedelta(seconds=random.randint(3, 20))
        ip, ua = random.choice(NORMAL_IPS), random.choice(NORMAL_USER_AGENTS)
        if random.random() < 0.2:
            status = 200 if random.random() > 0.05 else 401
            events.append((t, fmt(ip, t, "POST", "/login", status, ua)))
        else:
            events.append((t, fmt(ip, t, "GET", random.choice(NORMAL_PATHS), 200, ua)))

    # 2) credential stuffing burst (the SIGNATURE layer catches this)
    t = base + timedelta(hours=1)
    for i in range(150):
        t += timedelta(milliseconds=random.randint(50, 400))
        status = 200 if i == 149 else 401
        events.append((t, fmt(ATTACK_IP, t, "POST", "/login", status, BOT_UA)))

    # 3) scanner probing odd paths -> 404 (NO signature; the ANOMALY layer catches this)
    t = base + timedelta(hours=1, minutes=30)
    for _ in range(90):
        t += timedelta(milliseconds=random.randint(100, 600))
        events.append((t, fmt(SCANNER_IP, t, "GET", random.choice(ODD_PATHS), 404, SCANNER_UA)))

    events.sort(key=lambda e: e[0])
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(line for _, line in events) + "\n", encoding="utf-8")
    print(f"Wrote {len(events)} log lines (normal + credential stuffing + scanner)")


if __name__ == "__main__":
    main()