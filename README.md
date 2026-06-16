# log2sigma — Detection Rule Generator

Turns log anomalies into **tested, ATT&CK-mapped Sigma detection rules**.

- **Threat:** credential stuffing & other behavioral attacks in web/cloud logs
- **Technique:** MITRE ATT&CK `T1110.004` (Credential Stuffing) — more to come
- **Data:** Nginx access logs (CloudTrail next)
- **Approach:** detect anomaly -> auto-generate Sigma rule -> test against positive/negative fixtures in CI

> Status: in active development. Built as a detection-as-code (DaC) repo: every rule is
> version-controlled, mapped to an ATT&CK technique, and tested like production code.

## Why this exists

Operating a WAF blocks attacks that someone else's rules defined. This project goes one layer
deeper: it *finds* the attack pattern in raw logs, *codifies* it into a portable detection
rule, and *proves* the rule works — so a SIEM can catch it automatically at 3am.

## Repo layout

```
log2sigma/         # source package (parser, detectors, rule synthesis)
detections/        # generated rules, organized by ATT&CK technique
  T1110.004-credential-stuffing/
data/sample/       # small synthetic logs for demos & tests
tests/             # pytest: each rule tested vs known-good / known-bad logs
.github/workflows/ # CI: lint, type-check, rule validation, precision/recall gate
```

## Quickstart (filled in as the project is built)

```bash
uv sync                   # install dependencies
log2sigma generate --help # see the CLI (added in a later commit)
```
