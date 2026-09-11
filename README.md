# ThreatSight

[![CI](https://github.com/ellasypark/ThreatSight/actions/workflows/ci.yml/badge.svg)](https://github.com/ellasypark/ThreatSight/actions/workflows/ci.yml)

**Local-first web security investigation for small teams — no paid API required.**

Built from experience with expensive, complex enterprise security tools. ThreatSight helps investigate one question: **is this an attack, legitimate traffic blocked by the WAF, or an application failure?**

## System

```text
WAF + application events ──▶ Validate & calculate route metrics
                                       │
API contracts / release notes ──▶ BM25 context retrieval (RAG mode)
                                       │
                                       ▼
                          Rules or local LLM (Ollama)
                                       │
                                       ▼
                          Evidence-reference validation
                                       │
                                       ▼
                     HTML / JSON incident report
                 Findings · evidence · gaps · next checks
```

- **Service context:** normalized JSON events, shared request IDs, and service documents help investigate incidents; the rules baseline correlates WAF and app events by request ID and route.
- **Three comparable modes:** conservative rules, logs-only local LLM, or LLM + service-document RAG using BM25 lexical search.
- **Visible evidence:** route-level block/error rates, cited sources, missing evidence, and next checks. Model context is bounded to 40 current events and 3 documents.
- **Advisory output:** no production action tools. Invalid evidence references trigger abstention; valid citations do not guarantee correct reasoning.

## Quick start

Python 3.12+. From this repository's checkout:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Free, offline rules baseline — open the generated HTML in a browser
threatsight service-investigate tests/fixtures/service/app_error.json \
  --output reports/service-report.html
```

For local AI, install and start [Ollama](https://docs.ollama.com/quickstart), then:

```bash
ollama pull llama3.2:3b
threatsight service-investigate tests/fixtures/service/checkout_false_positive.json \
  --mode rag --model llama3.2:3b --output reports/checkout.html
```

Use `--mode llm` to compare without retrieved documents. Local inference uses your hardware; there is no paid API fallback. Inputs currently use a [normalized JSON format](docs/service-investigation.md), not native vendor exports.

## Evaluation

```bash
threatsight service-eval tests/fixtures/service/manifest.json \
  --modes rules,llm,rag --model llama3.2:3b
```

Reports precision/recall, abstention, retrieval Recall@3, citation-reference errors, tokens, and p50/p95 latency.

**Current result:** on six synthetic development cases, rules classified 4/6 correctly; the local 3B LLM and RAG modes each classified 2/6 correctly. AI has not yet outperformed the baseline. These are development checks, not a production benchmark. [Measured results and limitations →](reports/service-evaluation.md)

[Input & evaluation details](docs/service-investigation.md) · [Existing access-log detection pipeline](docs/legacy-pipeline.md) · [MIT License](LICENSE)
