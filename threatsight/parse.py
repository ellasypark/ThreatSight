"""
Nginx access-log parser.

A raw log line is just a long string. The detector can't reason about a string,
it needs structured fields. This turns ONE line like:

    45.143.220.81 - - [15/Jun/2026:03:00:00 +0000] "POST /login HTTP/1.1" 401 232 "-" "python-requests/2.31.0"

into a tidy object with: ip, timestamp, method, path, status, user_agent.

Run it from the project root:
    python -m log2sigma.parse
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

# One regex that pulls the fields we care about out of the 'combined' log format.
LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)


class LogEvent(BaseModel):
    """One parsed log line, with the field types we expect (validated by Pydantic)."""
    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    user_agent: str


def parse_line(line: str) -> LogEvent | None:
    """Turn one raw line into a LogEvent. Returns None if the line doesn't match."""
    m = LINE_RE.match(line.strip())
    if m is None:
        return None
    return LogEvent(
        ip=m["ip"],
        timestamp=datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z"),
        method=m["method"],
        path=m["path"],
        status=int(m["status"]),
        user_agent=m["ua"],
    )


def parse_file(path: str | Path) -> list[LogEvent]:
    """Parse every line in a log file, skipping any that don't match."""
    events = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        event = parse_line(line)
        if event is not None:
            events.append(event)
    return events


def main() -> None:
    events = parse_file("data/sample/access.log")
    print(f"Parsed {len(events)} events.")
    print("First event as structured fields:")
    print(events[0].model_dump())


if __name__ == "__main__":
    main()