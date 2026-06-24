# ThreatSight

An **AI-agent–powered detection & response analyzer** for web / WAF logs. It finds attacks
across three detection layers, lets an **LLM agent investigate them autonomously**, and maps
everything to **MITRE ATT&CK**.

## Why this exists

A busy web service logs **millions of requests a day**, and real attacks — credential stuffing,
SQL injection, scanning — hide among them. Two problems follow:

- **No one can read millions of log lines**, especially at 3am. Attacks get missed, or analysts
  drown in noise and alert fatigue.
- **Each traditional method falls short alone:** signature rules only catch attacks you already
  defined (they miss novel ones); pure anomaly detection is noisy; and even when an alert *does*
  fire, a human still has to investigate it and write it up — slow, and inconsistent between
  analysts and shifts.

ThreatSight tackles all of this at once: **layered detection** (known *and* unknown attacks), an
**agent that does the investigation for you**, and a **tested** pipeline so the alerts are
trustworthy.

## What it does

| Layer | Catches | How |
|---|---|---|
| **1. Signature** | known attacks | behaviour rules per ATT&CK technique (credential stuffing `T1110.004`, SQLi `T1190`) |
| **2. Anomaly** | unknown / novel attacks | robust statistical outlier detection per source IP (no signature needed) |
| **3. LLM** | obfuscated / context-dependent | Claude structured extraction (schema-validated) |
| **Agent** | the investigation itself | a Claude **tool-use loop** that pivots, enriches, maps to ATT&CK, and writes the assessment |

## What you get (the effect)

- **Fewer blind spots** — signatures catch the known, anomaly detection catches the *unknown*. A
  scanner with no written rule still gets flagged because it behaves unlike everyone else.
- **Investigation, not just alerts** — the agent turns *"an alert fired"* into *"here's who, what,
  how severe, and what to do"* — in seconds, the same way every time, 24/7. No analyst writing it
  up by hand at 3am.
- **Trustworthy alerts (low false positives)** — every detector is tested against labelled
  good/bad data, and CI gates precision/recall, so the tool doesn't cry wolf.
- **A shared language** — every finding is mapped to MITRE ATT&CK, with a coverage view of what
  you can and can't detect.
- **Portable & light** — runs on any web/WAF log, via CLI or a web dashboard, with no
  Elasticsearch / Kibana / Docker to operate.

## Install & use

```bash
pip install .                              # installs deps + the `threatsight` command

threatsight generate                       # make synthetic sample logs
threatsight analyze     data/sample/access.log          # rules: signature + anomaly (fast, free)
threatsight analyze     data/sample/access.log --format json
threatsight ai-analyze  data/sample/access.log          # LLM analysis (Claude)      [ANTHROPIC_API_KEY]
threatsight investigate data/sample/access.log          # agentic investigation loop [ANTHROPIC_API_KEY]
threatsight emulate                        # purple-team coverage matrix
uvicorn threatsight.server:app --reload    # web dashboard at http://127.0.0.1:8000
```

## The agent (why it's the core)

`orchestrator.py` is a Claude **tool-use loop** — the model decides which tools to call, observes
the results, and iterates to a final incident assessment. This is what makes ThreatSight
*investigate* rather than just *alert*.

- **Tools:** `run_signature_detectors`, `run_anomaly_detection`, `get_events_for_ip` (forensic
  pivot), `lookup_attack_technique`, `check_ip_reputation`
- **Context management:** tools return small summaries, never the raw log lines — so the model
  reasons over a tiny, relevant context instead of 100K events
- **Guardrails:** per-step tracing, tool errors fed back to the model, a `max_steps` cost bound

## Repo layout

```
threatsight/
  generate.py     # synthetic logs (normal + credential stuffing + scanner + SQLi)
  parse.py        # log line -> validated LogEvent (Pydantic)
  detector.py     # LAYER 1 — signature detection
  anomaly.py      # LAYER 2 — behavioral anomaly detection
  ai_analyze.py   # LAYER 3 — LLM structured extraction (Claude)
  orchestrator.py # AGENT — Claude tool-use investigation loop
  attack.py       # MITRE ATT&CK enrichment from the official STIX dataset
  report.py       # triage report (markdown / JSON)
  server.py       # FastAPI server — web dashboard + /api/analyze
  frontend/       # web dashboard (Chart.js)
  emulate.py      # purple-team: emulate attacks + coverage matrix
  cli.py          # the `threatsight` CLI
tests/            # pytest: detections catch attacks, raise no false positives
.github/workflows/ci.yml
```

## Threat model

| Attack | ATT&CK | Layer |
|---|---|---|
| Credential stuffing | `T1110.004` | signature |
| SQL injection | `T1190` | signature |
| Scanning / recon | `T1595.002` | anomaly |
| Obfuscated / novel | model-assessed | LLM + agent |

## Tech

Python · Pydantic · Polars · numpy · mitreattack-python (ATT&CK STIX) · Anthropic Claude
(tool-use) · FastAPI · Chart.js · Typer · pytest · GitHub Actions

## Status

Portfolio project. Roadmap: LLM/agent-abuse detection (prompt injection, jailbreak) mapped to
OWASP-LLM / MITRE ATLAS; persistent event store + forensic query API.