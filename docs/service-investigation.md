# Service investigation contract

The service workflow is additive: `service-investigate` and `service-eval` do not replace the original access-log commands.

## Input

A JSON object has `service`, `events`, and `documents`. Every source ID must be unique. Every `(source, window, request_id)` must be unique; pre-aggregate duplicate records from the same source. Unknown fields are rejected to prevent accidental evaluation-label ingestion.

```json
{
  "service": "My storefront",
  "events": [
    {"id":"w1","request_id":"r1","source":"waf","window":"current","path":"/checkout","status":200,"action":"allow"},
    {"id":"a1","request_id":"r1","source":"app","window":"current","path":"/checkout","status":503,"message":"Payment provider timeout"}
  ],
  "documents": [
    {"id":"runbook","title":"/checkout timeouts","text":"Check provider availability and application traces."}
  ]
}
```

Allowed sources: `waf`, `app`. Windows: `baseline`, `current`. Actions: `allow`, `block`, `observe`. Events may include `rule_id` and `message`. This version does not ingest timestamps or validate document chronology. The operator must select a coherent incident window and documents that were available then. Do not combine unrelated incidents into one bundle.

Bounds: 10,000 events, 100 documents, 1,000 characters per event message, 4,000 per document. This is for small incident bundles, not bulk log storage. No rate delta is produced when a source is absent in either window. A 5xx rate uses application-event count; a block rate uses WAF-event count.

## Methods

- Rules: conservatively identifies app failures linked to allowed WAF requests on the same route. Blocks alone result in abstention. This baseline does not attempt general attack classification.
- LLM: supplies route aggregates and up to 40 current events, prioritizing blocks and server errors.
- RAG: the same prompt and event selection plus up to 3 positively scoring BM25 documents. Exact route/rule terms and message words form the query. There is no automatic corpus download.

The local model returns a Pydantic-validated assessment. Every claim requires evidence IDs. Unknown references or an uncited non-abstaining conclusion cause the assessment to be rejected and replaced with abstention. Existing but misleading citations can still pass; do not call this semantic verification.

## Evaluation

The separate manifest lists `file`, `expected`, and `relevant_documents`. It must remain outside model input. Case-level labels use `attack_suspected`, `false_positive_suspected`, `app_error`, or `insufficient_evidence`.

Precision has the predicted-class count as denominator; recall has the ground-truth-class count. Missing denominators produce null. Failed calls count against overall accuracy and are separately counted as errors, not abstentions. Abstention rate uses all cases as denominator. Answered accuracy excludes abstentions and errors; read it alongside coverage/errors. Retrieval Recall@3 averages cases with annotated relevant documents only. p95 uses nearest rank. The run includes each full result to allow manual claim auditing.

Six included cases were written for development. Their narratives make some decisions easy and their labels are not independently adjudicated. Do not tune on these cases and then claim held-out performance. Add a separate test manifest with unseen services, routes, benign edge cases, attacks, and adversarial documents before drawing quality conclusions. No LLM judge is used to manufacture a hallucination score.

Reproducibility fields include OS/architecture/Python, model name, fixture SHA-256, and actual token counts where returned. Model name is not an immutable model digest; record the local model digest and Ollama version with any published run. Latency includes model loading and will differ on subsequent runs. Hardware utilization, energy, and human time-to-triage are not measured.

## Local API reference

The adapter uses [Ollama chat](https://docs.ollama.com/api/chat) with [structured outputs](https://docs.ollama.com/capabilities/structured-outputs), no streaming, a 120-second timeout, temperature 0, and a 1,200-output-token limit. The local server must already be running. Failed or malformed responses surface as errors; there is no hidden paid fallback.
