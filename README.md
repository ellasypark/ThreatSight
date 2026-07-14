# ThreatSight

[![CI](https://github.com/ellasypark/ThreatSight/actions/workflows/ci.yml/badge.svg)](https://github.com/ellasypark/ThreatSight/actions/workflows/ci.yml)

**An AI-agent–powered detection & response analyzer for web / WAF logs.** It triages raw access logs through four detection layers — including web-delivered malware — runs a **multi-agent LLM investigation** over the hits, and maps everything to **MITRE ATT&CK**, **OWASP**, and **MITRE ATLAS**, presented as a CLI report and a web dashboard.

> One line: *turn a noisy web/WAF log into a prioritized, framework-mapped incident report a responder can act on in minutes.*

<p align="center">
  <img src="docs/dashboard.jpg"  alt="ThreatSight dashboard top">
  <img src="docs/dashboard1.jpg" alt="ThreatSight dashboard bottom">
</p>

---

## Why this exists

A busy web service logs **millions of requests a day**, and real attacks — credential stuffing, SQL injection, scanning, web shells — hide among them. A WAF blocks and logs the flood, but the slow part of D&R isn't *blocking* — it's **deciding what actually matters, why, and what to do next.** Two problems follow:

- **No one can read millions of log lines**, especially at 3am. Attacks get missed, or analysts drown in alert fatigue.
- **Each method falls short alone:** signature rules only catch attacks you already defined; pure anomaly detection is noisy; and even when an alert fires, a human still has to investigate it — slow, and inconsistent across shifts.

ThreatSight tackles all of this at once: **layered detection** (known *and* unknown attacks, including post-compromise malware indicators), an **agent that does the investigation for you**, an **honest coverage view** of what it can't yet catch, and a **measured pipeline** validated on realistic traffic — not just a clean synthetic set.

---

## Architecture

![Architecture](docs/architecture.png)

```
access.log ─▶ parse ─▶ ┌─ signature   (cred stuffing, SQLi, scanning…)
                       ├─ malware     (web shell T1505.003, HTTP C2 T1071.001)
                       ├─ anomaly     (robust z-score / MAD on per-IP behavior)
                       └─ LLM         (Claude declarative extraction for obfuscated cases)
                                │
                                ▼
                     multi-agent investigation
                     triage ─▶ investigate (tool-use + RAG) ─▶ justify
                                │
                                ▼
              ATT&CK · OWASP · ATLAS mapping  ─▶  CLI report + web dashboard
```

---

## Detection layers

| Layer | Catches | How |
|---|---|---|
| **1. Signature** | known attacks | deterministic rules per ATT&CK technique (credential stuffing `T1110.004`, SQLi `T1190`) |
| **2. Malware** | web-delivered post-compromise | web shell interaction (`T1505.003`): scripts in writable dirs, known shell names, cmd-exec params; HTTP C2 beaconing (`T1071.001`): low-jitter cadence to one endpoint from a non-browser, non-monitor client |
| **3. Anomaly** | unknown / novel | robust z-score / MAD outlier detection per source IP — no signature needed |
| **4. LLM** | obfuscated / context-dependent | Claude tool-use forces findings into a typed Pydantic schema, with an explanation |

All deterministic layers are unit-tested and CI-gated; the LLM layer adds judgment on top, not in place of them.

The malware layer works within what a WAF/access log can actually see: the HTTP requests that interact with a dropped shell or that represent implant check-ins. It does not inspect uploaded file bytes or endpoint process trees — that is endpoint/sandbox territory and is stated as such.

---

## Semi-synthetic evaluation corpus

The performance numbers below come from a **semi-synthetic corpus** built by `threatsight corpus`. This matters because the alternative — measuring on a synthetic set where the same code writes the attacks and expects to catch them — produces 1.00/1.00/0.00 figures that don't reflect real traffic at all.

The corpus stacks two layers:

**Realistic benign base** (64 IPs) — not just normal users, but the hard negatives a real WAF faces: search-engine crawlers (Googlebot, Bingbot) that hit thousands of distinct paths and rack up 404s; uptime monitors (UptimeRobot, ELB health check) that beacon as regularly as C2; users who fat-finger a login. These are the false-positive traps that naive detectors fail on.

**Injected attack campaigns** (7 IPs, known ground truth):

| Technique | Attack | Detected by |
|---|---|---|
| T1110.004 | Credential stuffing | Signature |
| T1190 | SQL injection | Signature |
| T1505.003 | Web shell interaction | Malware (signature) |
| T1071.001 | HTTP C2 beaconing | Malware (behavioral) |
| T1595.002 | Vulnerability scanning | Anomaly |
| T1499 | HTTP flood | Anomaly |
| T1595.001 | Low-and-slow scraper | **missed** — honest gap |

A real log can be substituted as the benign base (NASA-HTTP, Zenodo, your own nginx logs) via `threatsight corpus --base your.access.log`. The label file (`data/corpus/labels.json`) records ground truth so the evaluation is reproducible.

---

## Measured performance

### Regression baseline (clean synthetic set, 53 IPs)

Reproducible with `threatsight metrics`. These are a **CI regression guard**, not a production benchmark — the set is clean by construction so the numbers are high.

| Detector | Precision | Recall | FP rate |
|---|---|---|---|
| Signature | 1.00 | 1.00 | 0.00 |
| Anomaly | 1.00 | 1.00 | 0.00 |
| Overall | 1.00 | 1.00 | 0.00 |

CI gates these: a change that breaks detection fails the build.

### Realistic corpus (semi-synthetic, 71 IPs, 9,876 events)

Reproducible with `threatsight corpus && threatsight metrics --corpus`. The benign base contains crawler/monitor FP-traps; 7 attack campaigns are injected with known ground truth.

| Detector | Precision | Recall | FP rate |
|---|---|---|---|
| Signature + Malware | 1.00 | 0.71 | 0.00 |
| Anomaly | 0.43 | 0.43 | 0.062 |
| Overall | 0.60 | 0.86 | 0.062 |

**Reading the numbers:** the deterministic layers (signature + malware) have zero false positives and catch what they're designed to catch. The 6.2% FP rate is entirely from the anomaly layer misfiring on search crawlers and uptime monitors — the FP-trap IPs — which is exactly where tuning work (adaptive thresholding, monitor allow-lists) should focus. The one missed attack is the low-and-slow scraper (`T1595.001`): volume, path diversity, and error rate all look human; only inter-request timing is mechanical. That gap is documented rather than hidden.

---

## Multi-agent investigation

`investigation/orchestrator.py` runs three roles in sequence — this is what makes ThreatSight *investigate* rather than just *alert*:

1. **Triage agent** — ranks the detected IPs by priority and disposition.
2. **Investigation agent** — a Claude **tool-use loop** with real tools: `run_signature_detectors`, `run_anomaly_detection`, `get_events_for_ip` (forensic pivot), `lookup_attack_technique`, `check_ip_reputation`, and **`search_attack_knowledge`** — **RAG** over the ATT&CK knowledge base (semantic embeddings via sentence-transformers, with a TF-IDF fallback).
3. **Justification agent** — writes the analyst-style assessment and recommended action.

**Context management:** tools return small summaries, never raw log lines, so the model reasons over a tiny relevant context instead of 100K events. **Guardrails:** per-step tracing, tool errors fed back to the model, and a `max_steps` cost bound.

## Framework mapping

Every finding maps to **MITRE ATT&CK** (technique, tactic, mitigations, data sources — from the official STIX dataset), **OWASP Top 10** (web) / **OWASP LLM Top 10**, and **MITRE ATLAS** for LLM-abuse cases. Stable frameworks use a static map; anything unrecognized is classified by the LLM.

## Threat model: coverage & gaps

`threat-model` asks the LLM to propose the ATT&CK/ATLAS techniques a given system is exposed to, then marks each as **covered**, **gap**, or **seen**. The dashboard renders this so a reviewer sees what ThreatSight does *not* yet catch — honest coverage, not a wall of green. The low-and-slow scraper above is a concrete example of a gap the coverage matrix surfaces.

---

## Install & use

```bash
git clone https://github.com/ellasypark/ThreatSight.git
cd ThreatSight
pip install .                              # installs deps + the `threatsight` command

threatsight generate                       # synthetic sample logs (normal + several attacks)
threatsight analyze data/sample/access.log # signature + anomaly + malware (fast, no API key)
threatsight analyze data/sample/access.log --format json
threatsight emulate                        # purple-team coverage matrix

# evaluation
threatsight metrics                        # regression baseline (clean set)
threatsight corpus                         # build semi-synthetic corpus (realistic base + injected attacks)
threatsight corpus --base your.access.log  # use a real log as the benign base
threatsight metrics --corpus               # realistic precision / recall / FP on the corpus

uvicorn threatsight.output.server:app --reload   # web dashboard at http://127.0.0.1:8000
```

### LLM features (Anthropic API key required)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."

threatsight ai-analyze  data/sample/access.log   # declarative extraction via Claude
threatsight investigate data/sample/access.log   # multi-agent triage → investigate → justify
threatsight threat-model --system "a public web app behind a WAF"
threatsight llm-scan                             # prompt-injection / jailbreak abuse (OWASP-LLM / ATLAS)
```

> If your network intercepts HTTPS and Anthropic calls fail with a certificate error, set `THREATSIGHT_INSECURE_SSL=1` for **local testing only**. Never commit this.

---

## Repo layout

```
threatsight/
  cli.py              # the `threatsight` CLI (entry point)
  config.py           # detection thresholds & tunables

  ingest/
    parse.py          # log line → validated LogEvent (Pydantic)
    generate.py       # synthetic logs (normal + attacks)
    corpus.py         # semi-synthetic evaluation corpus builder

  detection/
    detector.py       # LAYER 1 · signature rules (cred stuffing, SQLi)
    malware.py        # LAYER 2 · web-delivered malware (web shell, HTTP C2)
    anomaly.py        # LAYER 3 · behavioral anomaly (robust z-score / MAD)
    emulate.py        # purple-team: emulate attacks + coverage matrix

  investigation/
    ai_analyze.py     # LAYER 4 · LLM structured extraction (Claude)
    orchestrator.py   # multi-agent loop: triage → investigate → justify
    rag.py            # RAG over the ATT&CK KB (embeddings + TF-IDF fallback)
    llm_abuse.py      # LLM-request abuse detection (OWASP-LLM / ATLAS)

  enrichment/
    attack.py         # MITRE ATT&CK (official STIX dataset)
    owasp.py          # OWASP Top 10 / OWASP-LLM
    threat_model.py   # LLM-proposed threat profile + coverage/gaps

  evaluation/
    metrics.py        # precision / recall / FP — clean set and corpus

  output/
    report.py         # triage report (markdown / JSON)
    server.py         # FastAPI dashboard + /api/analyze
    frontend/         # web dashboard (Chart.js)

tests/                # pytest — fires on attacks, silent on benign and FP-traps
.github/workflows/ci.yml
pyproject.toml
README.md
```

---

## Tech

Python · Typer (CLI) · FastAPI + Chart.js (dashboard) · Pydantic · Polars / NumPy · Anthropic Claude (tool-use) · sentence-transformers (RAG) · mitreattack-python (ATT&CK STIX) · pytest + GitHub Actions CI

---

## Honest limits

- **Malware detection is network-layer only.** The malware layer detects web shell *interaction* (requests to a dropped shell) and HTTP C2 check-ins visible in the access log. It cannot inspect uploaded file bytes, disassemble binaries, or read endpoint process trees — that is endpoint/sandbox territory.
- **The corpus FP rate is an upper bound.** The benign base in a real-log corpus may contain an unlabelled real attack. If so, the measured FP rate is higher than the true FP rate for that traffic.
- **The LLM layers cost money and add latency.** All four detection layers and the full evaluation pipeline run without an API key; LLM features are opt-in.
- **Log data is untrusted input.** A crafted log line is a prompt-injection vector against the investigation agent, so its outputs are advisory, not authoritative.
- **Attribution is deliberately low-confidence.** Web-log TTPs are common to many actors; ThreatSight does not claim otherwise.

---

## License

MIT
