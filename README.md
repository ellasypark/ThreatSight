# ThreatSight

A WAF / web-log **threat analyzer** with two-layer detection, mapped to MITRE ATT&CK.

- **Layer 1 — Signature detection (known TTPs):** behaviour-based rules per attack technique (e.g. credential stuffing `T1110.004`).
- **Layer 2 — Behavioral anomaly detection (unknown):** robust statistical outlier detection over per-source-IP behaviour — catches novel / recon activity (e.g. a scanner) that **no signature was written for**.
- **ATT&CK enrichment:** technique names, tactics and links are pulled from the **official ATT&CK STIX dataset** (`mitreattack-python`) — not hardcoded.
- **Output:** a triage report (`reports/triage-report.md`) split into *signature detections* and *behavioral anomalies*, each with severity, ATT&CK mapping, and recommended actions.

> Built threat-first: model the attacks that apply, detect known ones precisely with signatures,
> and catch the unknown ones with anomaly detection — detection-as-code, not dashboard-clicking.
> (Runs on synthetic logs by design; swap in a public WAF dataset to analyse real traffic.)

## Why this exists

Operating a WAF at scale blocks attacks that someone else's rules defined. ThreatSight goes one
layer deeper: it *finds* attack patterns in raw logs, *maps* them to ATT&CK, and *reports* them so
a responder knows what happened and what to do — proving I understand the threat patterns behind
the blocks, not just the product.

## How it works

```
web/WAF logs
  -> parse        normalise to a validated schema (LogEvent)
  -> detector     Layer 1: signature detection of known TTPs
  -> anomaly      Layer 2: behavioural outlier detection (unknown/novel)
  -> attack       enrich each finding from the official ATT&CK STIX dataset
  -> report       triage report: signature detections + behavioral anomalies
```

**Anomaly method:** for each source IP we build a behavioural profile (request volume, 404 rate,
distinct paths probed, error rate) and flag IPs that are robust-z-score (median/MAD) outliers vs
the rest of the traffic. Findings include *why* they fired and a *candidate* ATT&CK technique for
analyst review.

## Threat model (what we detect, and why)

| Attack | ATT&CK | Layer | Log signal |
|---|---|---|---|
| Credential stuffing | `T1110.004` | signature | one IP, burst of 401s in 60s, scripted client |
| Scanning / recon | `T1595.002` | anomaly | many distinct paths, high 404 rate, outlier volume |
| SQL injection / XSS | `T1190` | signature *(planned)* | `' OR 1=1`, `<script>` in request params |
| L7 DoS | `T1499` / `T1498` | anomaly | abnormal request-rate spike from one source |

## Repo layout

```
threatsight/
  generate.py    # synthetic logs: normal + credential stuffing + scanner
  parse.py       # log line -> validated LogEvent
  detector.py    # Layer 1: signature detection (known TTPs)
  anomaly.py     # Layer 2: behavioural anomaly detection (unknown)
  attack.py      # ATT&CK STIX enrichment (mitreattack-python)
  report.py      # combined triage report
data/sample/     # small synthetic logs
data/attack/     # cached ATT&CK STIX dataset (gitignored, ~40 MB)
reports/         # generated triage report
```

## Quickstart

```bash
pip install mitreattack-python polars pydantic numpy tzdata

python -m threatsight.generate   # make sample logs (normal + 2 attacks)
python -m threatsight.report      # analyse -> reports/triage-report.md
```

> First run downloads the official ATT&CK STIX dataset (~40 MB) into `data/attack/` and caches it.