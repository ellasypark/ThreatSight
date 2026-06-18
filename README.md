# ThreatSight

A WAF / web-log **threat analyzer**: detects attack patterns and produces **MITRE ATT&CK–mapped threat reports**.

- **Threats:** credential stuffing, SQL injection, XSS, scanning/bots, L7 DoS
- **Technique mapping:** MITRE ATT&CK (`T1110.004`, `T1190`, `T1595`, `T1499` …), enriched from the official ATT&CK STIX dataset
- **Output:** threat report (top source IPs, attack timeline, confidence) + ATT&CK coverage heatmap; Sigma rules as a bonus
- **Data:** synthetic web logs (swap in a public WAF dataset)

> Built threat-first: I model which attacks apply to the system, derive the relevant ATT&CK
> techniques, build a detector per technique, and measure coverage — detection-as-code, not
> dashboard-clicking.

## Why this exists

Operating a WAF at scale blocks attacks that someone else's rules defined. ThreatSight goes one
layer deeper: it *finds* the attack patterns in raw logs, *maps* them to ATT&CK, and *reports*
them so a responder knows what happened and what to do — proving I understand the threat patterns
behind the blocks, not just the product.

## Pipeline

```
WAF/web logs
  -> parse        normalise to a validated schema (LogEvent)
  -> detectors/   one detector per attack technique (behaviour-based, not IOC blocklists)
  -> ATT&CK       enrich each detection from the official ATT&CK STIX data
  -> report       top attacker IPs, attack timeline, confidence, severity, recommended actions
  -> navigator    ATT&CK coverage heatmap (layer.json)
  -> sigma        (bonus) export detections as portable Sigma rules
```

## Threat model (what we detect, and why)

| Attack | ATT&CK | Log signal (procedure) |
|---|---|---|
| Credential stuffing | `T1110.004` | one IP, burst of 401s in 60s, scripted client |
| SQL injection | `T1190` | `' OR 1=1`, `UNION SELECT` in request params |
| XSS | `T1190` | `<script>`, `onerror=` in request params |
| Scanning / bots | `T1595.002` | path enumeration, 404 burst, bot UA |
| L7 DoS | `T1499` / `T1498` | abnormal request-rate spike from one source |

## Repo layout

```
log2sigma/        # source package (parser, detectors, report)
  generate.py     # synthetic normal + attack traffic (demo/test data)
  parse.py        # log -> validated LogEvent
  detect.py       # detector(s); grows into a detectors/ package
  report.py       # ATT&CK-mapped threat / triage report
detections/       # rules + test fixtures, organised by technique
data/sample/      # small synthetic logs
tests/            # pytest: each detector vs known-good / known-bad
.github/workflows/# CI: lint, type-check, precision/recall gate
```

> Note: the Python package folder is `log2sigma` (the project/repo is named **ThreatSight** —
> repo name and package name can differ). Rename the package later if you want them identical.

## Quickstart

```bash
uv sync
python -m log2sigma.generate   # make sample logs
python -m log2sigma.report     # analyse + write threat report
```