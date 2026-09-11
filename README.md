# ThreatSight

[![CI](https://github.com/ellasypark/ThreatSight/actions/workflows/ci.yml/badge.svg)](https://github.com/ellasypark/ThreatSight/actions/workflows/ci.yml)

**Local-first web security investigation for small teams.**

Is your service under attack, is the WAF blocking legitimate requests, or is the application failing?
ThreatSight connects WAF and application evidence, retrieves service-specific context, and produces an inspectable incident report. The default path runs without a model, paid API, vector database, or external service. Optional local LLM investigation uses Ollama.

## Why I am building this

Working with enterprise security tools exposed how expensive and difficult they can be to operate. ThreatSight explores a smaller alternative: help a service owner investigate one concrete problem, with visible evidence, explicit uncertainty, and measurable tradeoffs between quality and cost.

This is an early open-source prototype, not an enterprise SIEM replacement or a claim of production-grade detection. The goal is to measure how useful low-cost AI can be, rather than add agents for their own sake.

## Start without an API key

Requires Python 3.12+.

```bash
git clone https://github.com/ellasypark/ThreatSight.git
cd ThreatSight
python -m venv .venv
source .venv/bin/activate
pip install -e .

threatsight service-investigate tests/fixtures/service/app_error.json \
  --output reports/service-report.html
```

Open `reports/service-report.html` in a browser. It is a standalone report with no scripts, CDN assets, or server. The demo connects an allowed WAF request to an application failure using a shared request ID. Other fixtures cover suspected SQL injection, checkout false positives, ambiguous blocks, conflicting signals, and a log containing prompt injection.

## What is implemented

| Capability | Current implementation |
|---|---|
| Service impact | Per-route WAF block and app 5xx rates, denominators, baseline/current percentage-point changes |
| Correlation | Exact request ID and route correlation in the conservative rules baseline |
| Service-context RAG | Bounded BM25 lexical retrieval over supplied API contracts, release notes, and runbooks |
| Local AI | One bounded, schema-constrained Ollama call; no action tools or automatic changes |
| Inspectable results | Claims cite source IDs; missing evidence, next checks, and source content are shown |
| Evaluation | Rules vs logs-only LLM vs LLM + retrieved context; per-case outputs, metrics, environment, and fixture hashes |
| Existing research pipeline | Access-log signatures, anomaly detection, ATT&CK mapping, and optional Claude investigation remain available |

RAG here is **lexical retrieval plus generation**, not semantic or hybrid search. The new service investigator is a single bounded model call, not an autonomous multi-agent system. The older ATT&CK RAG pipeline is separate.

## Local LLM and RAG

Install and start [Ollama](https://docs.ollama.com/quickstart), then pull a model supported by your hardware. For example:

```bash
ollama pull llama3.2:3b
threatsight service-investigate tests/fixtures/service/checkout_false_positive.json \
  --mode rag --model llama3.2:3b --output reports/checkout.html
```

`--mode llm` uses the same model and event selection without retrieved documents. `--mode rules` makes no model call. There is no automatic model download or paid-provider fallback. The Ollama endpoint is fixed to loopback, ignores proxy settings, and does not follow redirects. Configure Ollama for local models; ThreatSight does not control the server's own configuration.

Local inference still consumes memory, electricity, and time. A zero paid-API charge is not zero total operating cost. Model quality and latency depend on the model and hardware.

## Bring your own service evidence

The first supported input is a **normalized JSON bundle**, not a native AWS/Cloudflare export. See [the input and evaluation guide](docs/service-investigation.md) and the [checkout example](tests/fixtures/service/checkout_false_positive.json).

- Events identify source (`waf` or `app`), request ID, route, status, WAF action, and window (`baseline` or `current`).
- Documents contain a source ID, title, and text. Supply only knowledge available at investigation time.
- Evaluation labels live in a separate manifest and are not passed to the investigator.

Use comparable windows and disclose sampling. Requests blocked at the edge may have no application event. Missing application data is not proof of safety. A blocked-request count is not an attack count.

## Reproduce the comparison

```bash
pip install -e '.[dev]'
pytest

# Fully offline baseline
threatsight service-eval tests/fixtures/service/manifest.json

# Actual local-model comparison; never substitutes rules for a failed model call
threatsight service-eval tests/fixtures/service/manifest.json \
  --modes rules,llm,rag --model llama3.2:3b \
  --output reports/service-evaluation.json
```

See [the measured development run](reports/service-evaluation.json) and [readable results](reports/service-evaluation.md). These are **six synthetic development cases**, including intentionally ambiguous cases. They are smoke tests and a starting point for evaluation, not a held-out benchmark or proof of superiority to commercial products.

The evaluator reports classification precision/recall, accuracy including errors, abstention, accuracy on answered cases, retrieval Recall@3, invalid-citation claim rate, token usage, and p50/p95 latency. Unknown metrics remain `null`. Citation existence is not semantic correctness: unsupported-claim rate and prompt-injection attack success require separate annotations and are not claimed as measured. This run is too small for generalization.

## Design boundaries

- No automatic WAF rule deployment, blanket exceptions, or production replay. Rule deployment belongs in [CortexWAF](https://github.com/ellasypark/CortexWAF).
- Logs and retrieved documents are untrusted input. There are no action tools; schema and citation checks constrain outputs but do not solve prompt injection or hallucination.
- Model context contains at most 40 current events and 3 documents. Truncation is disclosed; all input events contribute to route statistics.
- Source content appears in local reports. Remove secrets and personal data before sharing a bundle or report; automatic redaction is not implemented.
- Baseline windows and document validity are supplied by the operator. The tool does not infer causality from coincident changes.

## Existing access-log workflow

```bash
threatsight analyze data/sample/access.log
threatsight corpus
threatsight metrics --corpus
uvicorn threatsight.output.server:app --host 127.0.0.1
```

The existing dashboard remains the access-log dashboard; the new service report is generated separately. See [the original pipeline documentation](docs/legacy-pipeline.md) for detection methods and corpus limitations.

Heavy dependencies are now optional: `pip install -e '.[ai]'` for legacy Claude features, `.[semantic]` for legacy embedding retrieval, `.[attack]` for STIX support, or `.[full]` for all three. Legacy API features still require an Anthropic key. The base installation no longer downloads these packages.

## Next research steps

Collect independently labeled cases; add vendor-log adapters and timestamp-aware context; compare lexical and hybrid retrieval; evaluate semantic claim support and adversarial robustness; measure installation effort and hardware usage. These are future work, not shipped features.

## License

MIT — see [LICENSE](LICENSE).
