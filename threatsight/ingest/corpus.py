"""
Semi-synthetic evaluation corpus: real (or realistic) benign traffic + injected attacks.

WHY THIS EXISTS
---------------
`metrics.py` measures on a *clean* synthetic set where the same code writes the
attacks and expects to catch them — a circular test that reports precision 1.00.
On real traffic the numbers are lower, because real *benign* traffic contains
things that LOOK like attacks: search-engine crawlers hit thousands of distinct
paths and rack up 404s, uptime monitors hammer one endpoint, users fat-finger a
login. Those are the false positives a WAF actually has to suppress.

This module builds an honest test set:

    benign base  (real access log  OR  a realistic synthesiser with FP traps)
        +  injected attack campaigns  (known IPs, known techniques, known windows)
        =  access.log  +  labels.json  (ground truth for measuring FP on noise)

The benign base is treated as ground-truth NEGATIVE and the injected campaigns as
ground-truth POSITIVE. This is the standard semi-synthetic assumption; its one
caveat is stated honestly in `labels.json.meta` and in the README: a real log may
contain an *un-labelled* real attack, so measured FP is an upper bound on true FP.

Run from the project root:
    python -m threatsight.corpus                      # synthetic realistic base
    python -m threatsight.corpus --base some.access.log   # drop in a real log
Output: data/corpus/access.log  +  data/corpus/labels.json
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .parse import LogEvent, parse_file

OUT_DIR = Path("data/corpus")
OUT_LOG = OUT_DIR / "access.log"
OUT_LABELS = OUT_DIR / "labels.json"

# ── benign fleet ────────────────────────────────────────────────────────────
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5) AppleWebKit/605.1.15 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101 Firefox/127.0",
]
# Real crawlers / monitors: legitimate, but BEHAVIOURALLY attack-like → FP traps.
GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
BINGBOT_UA = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
MONITOR_UA = "UptimeRobot/2.0 (+http://uptimerobot.com/)"
HEALTHCHECK_UA = "ELB-HealthChecker/2.0"

# A real site's URL space: a long tail, so crawlers legitimately touch many paths.
CONTENT_PATHS = (
    ["/", "/home", "/products", "/products/{}", "/cart", "/search?q={}", "/account",
     "/blog", "/blog/{}", "/about", "/contact", "/pricing", "/faq", "/category/{}"]
)
STATIC_CASCADE = ["/static/app.css", "/static/app.js", "/static/logo.png", "/favicon.ico"]

# ── attack tradecraft (each maps to a detector + an ATT&CK technique) ─────────
CRED_STUFF_UA = "python-requests/2.31.0"
SQLMAP_UA = "sqlmap/1.7.11#stable"
SCANNER_UA = "curl/8.4.0"
# "Gray-market" scraper: a *legit* browser UA, under rate limits, but mechanical.
SCRAPER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"

SQLI_PAYLOADS = [
    "/search?q=1'OR'1'='1",
    "/item?id=1'OR'1'='1--",
    "/news?id=1)UNION/**/SELECT/**/pass/**/FROM/**/users",
    "/p?id=1'AND'1'='1",
]
ODD_PATHS = [
    "/admin", "/wp-login.php", "/.env", "/phpmyadmin", "/api/v1/users", "/config.php",
    "/backup.zip", "/.git/config", "/server-status", "/shell.php", "/.aws/credentials",
    "/vendor/phpunit", "/.ssh/id_rsa", "/actuator/env",
]


def _fmt(ip: str, when: datetime, method: str, path: str, status: int, ua: str) -> str:
    ts = when.strftime("%d/%b/%Y:%H:%M:%S %z")
    size = random.randint(120, 5200)
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def _diurnal_weight(hour: int) -> float:
    """Traffic multiplier by hour — a real site has a daytime peak and a 3am trough.

    This is what makes a *static* threshold fail: the same request rate that is
    normal at 2pm is a flood at 4am. It's the hook the adaptive-threshold work
    (JD bullet #1) will exploit.
    """
    import math

    # peak ~14:00, trough ~04:00, never zero.
    return 0.25 + 0.75 * (0.5 * (1 + math.cos((hour - 14) / 24 * 2 * math.pi)))


# ── benign base ──────────────────────────────────────────────────────────────
def synth_base(day: datetime, rng: random.Random) -> tuple[list[str], dict]:
    """Realistic benign traffic over 24h. Returns (log_lines, ip_roles).

    ip_roles marks which benign IPs are *borderline* (crawlers/monitors) so we can
    report separately how many false positives came from the genuinely hard cases.
    """
    lines: list[str] = []
    roles: dict[str, str] = {}

    # 1) human browsing sessions — page load pulls a static-asset cascade.
    humans = [f"203.0.113.{n}" for n in range(2, 62)]
    for ip in humans:
        roles[ip] = "human"
        hour = rng.choices(range(24), weights=[_diurnal_weight(h) for h in range(24)])[0]
        t = day + timedelta(hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        for _ in range(rng.randint(2, 6)):  # a few page views per session
            t += timedelta(seconds=rng.randint(4, 40))
            page = rng.choice(CONTENT_PATHS).format(rng.randint(1, 400))
            lines.append(_fmt(ip, t, "GET", page, 200, rng.choice(BROWSER_UAS)))
            for asset in STATIC_CASCADE:  # real browsers fetch sub-resources
                t += timedelta(milliseconds=rng.randint(20, 200))
                lines.append(_fmt(ip, t, "GET", asset, 200, rng.choice(BROWSER_UAS)))
            if rng.random() < 0.12:  # occasional login, sometimes a benign typo (401)
                t += timedelta(seconds=rng.randint(2, 8))
                status = 200 if rng.random() > 0.25 else 401
                lines.append(_fmt(ip, t, "POST", "/login", status, rng.choice(BROWSER_UAS)))
            if rng.random() < 0.06:  # stale bookmark → benign 404
                t += timedelta(seconds=1)
                lines.append(_fmt(ip, t, "GET", "/blog/old-post", 404, rng.choice(BROWSER_UAS)))

    # 2) search crawlers — high request count, MANY distinct paths, some 404.
    #    Naive anomaly (distinct_paths / not_found_ratio / requests z-score) will
    #    want to flag these. They are the headline false-positive trap.
    for ip, ua in [("66.249.66.1", GOOGLEBOT_UA), ("157.55.39.10", BINGBOT_UA)]:
        roles[ip] = "crawler"
        t = day
        for _ in range(rng.randint(70, 110)):
            t += timedelta(seconds=rng.randint(5, 40))
            path = rng.choice(CONTENT_PATHS).format(rng.randint(1, 900))
            status = 200 if rng.random() > 0.10 else 404  # crawlers hit dead links
            lines.append(_fmt(ip, t, "GET", path, status, ua))

    # 3) uptime monitor + load-balancer health check — one path, high frequency.
    #    Trips the `requests` volume feature; single-path so distinct_paths stays low.
    for ip, ua, path, every in [
        ("198.51.100.7", MONITOR_UA, "/health", 60),
        ("10.0.0.5", HEALTHCHECK_UA, "/status", 15),
    ]:
        roles[ip] = "monitor"
        t = day
        while t < day + timedelta(hours=24):
            t += timedelta(seconds=every + rng.randint(-2, 2))
            lines.append(_fmt(ip, t, "GET", path, 200, ua))

    return lines, roles


def load_real_base(path: str | Path) -> tuple[list[str], dict]:
    """Use a REAL access log as the benign base (NASA-HTTP, Zenodo, your own nginx).

    Every source IP in a real log is assumed benign (semi-synthetic assumption).
    We keep the raw lines verbatim so the parser is exercised on real-world messiness.
    """
    events = parse_file(path)
    if not events:
        raise ValueError(f"No parseable combined-format lines in {path}")
    raw = [ln for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]
    roles = {e.ip: "real" for e in events}
    return raw, roles


# ── attack injection ─────────────────────────────────────────────────────────
def inject_attacks(day: datetime, rng: random.Random) -> tuple[list[str], dict]:
    """Overlay attack campaigns. Returns (log_lines, labels) with known ground truth.

    Each campaign has a distinct source IP, technique, and time window so metrics
    can score per-technique, not just overall.
    """
    lines: list[str] = []
    labels: dict[str, dict] = {}

    def _window(start: datetime, end: datetime):
        return [start.isoformat(), end.isoformat()]

    # A) credential stuffing — burst of failed logins (signature T1110.004).
    ip = "45.143.220.81"
    t0 = day + timedelta(hours=3, minutes=12)
    t = t0
    for i in range(140):
        t += timedelta(milliseconds=rng.randint(40, 350))
        status = 200 if i == 139 else 401  # one eventual success
        lines.append(_fmt(ip, t, "POST", "/login", status, CRED_STUFF_UA))
    labels[ip] = {"attack": "credential_stuffing", "technique": "T1110.004",
                  "window": _window(t0, t)}

    # B) SQL injection — payloads in the query string (signature T1190).
    ip = "91.92.240.10"
    t0 = day + timedelta(hours=9, minutes=40)
    t = t0
    for _ in range(16):
        t += timedelta(milliseconds=rng.randint(200, 900))
        lines.append(_fmt(ip, t, "GET", rng.choice(SQLI_PAYLOADS), 200, SQLMAP_UA))
    labels[ip] = {"attack": "sql_injection", "technique": "T1190", "window": _window(t0, t)}

    # C) vulnerability scanner — probes odd paths → 404 (anomaly layer).
    ip = "185.220.101.5"
    t0 = day + timedelta(hours=15, minutes=5)
    t = t0
    for _ in range(80):
        t += timedelta(milliseconds=rng.randint(80, 500))
        lines.append(_fmt(ip, t, "GET", rng.choice(ODD_PATHS), 404, SCANNER_UA))
    labels[ip] = {"attack": "scanning", "technique": "T1595.002", "window": _window(t0, t)}

    # D) HTTP flood at 4am — high volume during the diurnal TROUGH. Caught today by
    #    the total-volume anomaly feature, but that feature is time-blind: it's the
    #    same raw-count heuristic that misfires on crawlers/monitors below. A rate-based
    #    detector with a diurnal-adaptive threshold would catch the flood *without* the
    #    collateral FP. (JD bullet #1: intelligent CC / HTTP-flood mitigation.)
    ip = "193.32.162.20"
    t0 = day + timedelta(hours=4)  # deliberately off-peak
    t = t0
    for _ in range(900):
        t += timedelta(milliseconds=rng.randint(15, 90))
        lines.append(_fmt(ip, t, "GET", rng.choice(["/", "/search?q=a", "/products"]), 200, CRED_STUFF_UA))
    labels[ip] = {"attack": "http_flood", "technique": "T1499", "window": _window(t0, t)}

    # E) low-and-slow "gray-market" scraper — LEGIT browser UA, UNDER rate limits,
    #    but mechanically uniform timing and sequential ID walk. Rate/volume rules
    #    miss it; only behavioural timing analysis catches it.
    #    (JD bullet #2: smart bot behaviour detection.) Left un-caught on purpose
    #    today so the coverage matrix shows an honest GAP the internship would fill.
    #    It re-checks a SMALL fixed catalogue (like a price monitor), so distinct_paths,
    #    404-ratio and request VOLUME all stay inside the benign range — the only tell is
    #    the metronome-uniform cadence, which no current detector measures. Left as an
    #    honest coverage GAP: the behavioural timing analysis in JD bullet #2 would fill it.
    ip = "104.28.51.77"
    t0 = day + timedelta(hours=11)
    t = t0
    catalogue = [f"/products/{pid}" for pid in range(101, 111)]  # 10 watched items
    for _cycle in range(3):                                       # 30 reqs, 10 paths, all 200
        for path in catalogue:                                    # → volume & paths look human
            t += timedelta(seconds=40)  # but the cadence is a metronome; a human's never is
            lines.append(_fmt(ip, t, "GET", path, 200, SCRAPER_UA))
    labels[ip] = {"attack": "scraping_bot", "technique": "T1595.001", "window": _window(t0, t)}

    # F) web shell — after a (malicious) upload, the attacker interacts with a shell
    #    dropped in a writable dir. The access log sees the requests to that URL, not
    #    the uploaded bytes. (ATT&CK T1505.003 — web-delivered malware.)
    ip = "45.61.150.9"
    t0 = day + timedelta(hours=16, minutes=20)
    t = t0
    lines.append(_fmt(ip, t, "POST", "/upload.php", 200, SCANNER_UA))  # the drop
    for _ in range(14):  # command execution through the shell
        t += timedelta(seconds=rng.randint(3, 25))
        cmd = rng.choice(["?cmd=whoami", "?cmd=id", "?c=cat+/etc/passwd", "?exec=ls+-la", "?cmd=uname+-a"])
        lines.append(_fmt(ip, t, "POST", f"/uploads/shell.php{cmd}", 200, SCANNER_UA))
    labels[ip] = {"attack": "web_shell", "technique": "T1505.003", "window": _window(t0, t)}

    # G) HTTP C2 beacon — an implant checks in on a low-jitter cadence to one endpoint
    #    with a non-browser UA. Distinguished from a benign uptime monitor by the UA
    #    allow-list in malware.py. (ATT&CK T1071.001.)
    ip = "23.106.223.47"
    t0 = day + timedelta(hours=6)
    t = t0
    for _ in range(40):  # ~every 30s ±small jitter → very regular
        t += timedelta(seconds=30 + rng.uniform(-1.5, 1.5))
        lines.append(_fmt(ip, t, "GET", "/api/v1/jobs", 200, "Go-http-client/1.1"))
    labels[ip] = {"attack": "c2_beacon", "technique": "T1071.001", "window": _window(t0, t)}

    return lines, labels


# ── orchestration ────────────────────────────────────────────────────────────
def build_corpus(base_path: str | Path | None = None, seed: int = 1337) -> dict:
    """Assemble base + attacks, write access.log + labels.json, return a summary."""
    rng = random.Random(seed)
    day = datetime(2026, 6, 15, 0, 0, 0, tzinfo=timezone.utc)

    if base_path:
        base_lines, roles = load_real_base(base_path)
        base_desc = f"real:{base_path}"
    else:
        base_lines, roles = synth_base(day, rng)
        base_desc = "synthetic-realistic"

    attack_lines, malicious = inject_attacks(day, rng)

    # Guard: an injected attacker must not collide with a benign base IP.
    overlap = set(malicious) & set(roles)
    if overlap:
        raise ValueError(f"attack IP collides with benign base IP: {overlap}")

    all_lines = base_lines + attack_lines
    # Sort by parsed timestamp so the log is chronological like a real one.
    parsed = [(parse_file_line(ln), ln) for ln in all_lines]
    parsed = [(ev, ln) for ev, ln in parsed if ev is not None]
    parsed.sort(key=lambda p: p[0].timestamp)
    ordered = [ln for _, ln in parsed]

    benign_ips = [ip for ip, r in roles.items() if r != "borderline"]
    borderline = [ip for ip, r in roles.items() if r in ("crawler", "monitor")]

    labels = {
        "meta": {
            "generated": datetime.now(timezone.utc).isoformat(),
            "base": base_desc,
            "seed": seed,
            "n_events": len(ordered),
            "caveat": ("Benign base assumed attack-free (semi-synthetic). A real base "
                       "may contain an un-labelled real attack, so measured FP is an "
                       "upper bound on true FP."),
        },
        # ground truth for scoring:
        "malicious": malicious,                       # positive class (IP → attack)
        "benign_ips": sorted(benign_ips),             # negative class
        "borderline_ips": sorted(borderline),         # the hard negatives (FP traps)
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_LOG.write_text("\n".join(ordered) + "\n", encoding="utf-8")
    OUT_LABELS.write_text(json.dumps(labels, indent=2), encoding="utf-8")
    return {"events": len(ordered), "benign": len(benign_ips),
            "borderline": len(borderline), "attacks": len(malicious), "base": base_desc}


def parse_file_line(line: str) -> LogEvent | None:
    """Local re-export so sorting doesn't import a private name."""
    from .parse import parse_line

    return parse_line(line)


def main(base: str | None = None) -> None:
    s = build_corpus(base)
    print(f"Wrote {s['events']} lines to {OUT_LOG}  (base: {s['base']})")
    print(f"  {s['attacks']} attack IPs · {s['benign']} benign IPs "
          f"({s['borderline']} borderline crawler/monitor FP-traps)")
    print(f"  ground truth: {OUT_LABELS}")


if __name__ == "__main__":
    import sys

    arg = None
    if "--base" in sys.argv:
        arg = sys.argv[sys.argv.index("--base") + 1]
    main(arg)