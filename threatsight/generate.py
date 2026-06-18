"""
Synthetic Nginx access-log generator.

We need realistic data to build a detection on, so this makes two kinds of traffic:

  1. NORMAL  - many different users, real browsers, mostly successful logins.
  2. ATTACK  - ONE ip doing credential stuffing: a 2-minute burst of failed
               logins from a scripted (non-browser) client, ending in a single
               success -> the moment an account gets taken over.

Run it from the project root:

    python -m log2sigma.generate

Output: data/sample/access.log
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUTPUT = Path("data/sample/access.log")

# Real browsers a human would use.
NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Version/17.5 Mobile Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/127.0",
    "Mozilla/5.0 (Linux; Android 14) Chrome/126.0 Mobile Safari/537.36",
]

# A script, NOT a browser. This is the tell-tale sign of automation.
ATTACK_USER_AGENT = "python-requests/2.31.0"

NORMAL_IPS = [f"203.0.113.{n}" for n in range(2, 60)]  # many different users
ATTACK_IP = "45.143.220.81"                            # one attacker


def fmt(ip: str, when: datetime, status: int, ua: str) -> str:
    """Format ONE line in Nginx 'combined' log format (status 200 = ok, 401 = login failed)."""
    ts = when.strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{ts}] "POST /login HTTP/1.1" {status} 232 "-" "{ua}"'


def normal_traffic(start: datetime, n: int = 200) -> list[tuple[datetime, str]]:
    """Real users over ~1 hour. Mostly 200 (success), ~5% 401 (someone mistyped)."""
    events, t = [], start
    for _ in range(n):
        t += timedelta(seconds=random.randint(5, 25))      # spread out in time
        ip = random.choice(NORMAL_IPS)
        ua = random.choice(NORMAL_USER_AGENTS)
        status = 200 if random.random() > 0.05 else 401
        events.append((t, fmt(ip, t, status, ua)))
    return events


def attack_traffic(start: datetime, n: int = 150) -> list[tuple[datetime, str]]:
    """Credential stuffing: one IP, fast burst, almost all 401, the LAST one a 200."""
    events, t = [], start
    for i in range(n):
        t += timedelta(milliseconds=random.randint(50, 400))  # many tries per second
        status = 200 if i == n - 1 else 401                   # last guess works -> breach
        events.append((t, fmt(ATTACK_IP, t, status, ATTACK_USER_AGENT)))
    return events


def main() -> None:
    random.seed(42)  # fixed seed -> same file every run (handy for tests later)
    base = datetime(2026, 6, 15, 2, 0, 0, tzinfo=timezone.utc)

    events = normal_traffic(base)                              # normal all hour
    events += attack_traffic(base + timedelta(hours=1))        # attack hits at ~3am
    events.sort(key=lambda e: e[0])                            # interleave by time

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(line for _, line in events) + "\n", encoding="utf-8")

    print(f"Wrote {len(events)} log lines to {OUTPUT}")
    print(f"  normal users + one attacker ({ATTACK_IP})")


if __name__ == "__main__":
    main()