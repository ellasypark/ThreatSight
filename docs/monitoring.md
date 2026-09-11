# Continuous local monitoring

## Start and stop

`threatsight monitor access.log app.jsonl --db data/monitor.sqlite --port 8765`

The foreground process continuously tails the selected files and serves a read-only dashboard on `127.0.0.1`. Stop with Ctrl+C. Use one process per SQLite database. This is not an installed operating-system service; monitoring stops when the process stops. Start it again with the same database to resume checkpoints and incidents. The original `uvicorn threatsight.output.server:app` command still serves the older snapshot dashboard, not this monitor.

The collector runs every two seconds by default (`--interval`). The dashboard polls every two seconds and explicitly shows disconnected/stale state on request failure. The UI has no external assets. File contents appear as text, not HTML. Do not expose this unauthenticated local service through a public proxy.

## Input formats

**nginx combined access log:** parsed as web/application traffic. The path is separated from the query for grouping, while the bounded request target is retained as evidence. HTTP response codes are observable service signals, not proof of compromise.

**Application JSONL:** one object per newline. Example:

```json
{"timestamp":"2026-09-11T01:00:00Z","source":"app","request_id":"r1","path":"/checkout","status":503,"message":"Payment provider timeout"}
```

Only `path` and `status` are required. Source defaults to `app`; missing request IDs get a collector-generated ID. Optional fields: `timestamp`, `source` (`app`/`waf`), `request_id`, `action` (`allow`/`block`/`observe`), `rule_id`, `message`. The investigator's existing event length limits apply. Use normalized route paths to avoid high-cardinality grouping. WAF exports need conversion to this schema; there are no native AWS or Cloudflare connectors.

```json
{"source":"waf","request_id":"r1","path":"/checkout","status":403,"action":"block","rule_id":"SQL-942","message":"Rule matched"}
```

Do not ingest the same stream through multiple paths. Counts are records per source, not deduplicated business transactions or unique visitors. Application and WAF counts have separate denominators.

## Timing, checkpoints, and retention

- Live windows use **collection time**, not event time. Original timestamps are retained in storage. On first use, the collector reads existing contents from the beginning; backfill can trigger incidents. Start with an empty/new log for a clean live demo.
- File identity, byte offset, and an anchor are persisted with accepted records. Restarting the same database does not re-read committed lines.
- Rename/create rotation and detected copy-truncation reset the cursor. Unread bytes in a renamed-away file are not drained. Rapid copy-truncate/regrowth with an identical anchor may be undetectable; this is not an exactly-once production collector.
- Up to 1,000 complete lines per source per poll. An incomplete final line waits for its newline. Malformed complete lines are skipped and counted. A line exceeding 64 KiB pauses that source and exposes an error; fix/rotate the source to resume.
- Source records retain 24 hours. Resolved incidents retain 30 days. Each incident keeps up to 40 matching evidence records; the dashboard shows the newest 100 incidents. Storage size scales with traffic; no disk quota is enforced.
- Source states: receiving, idle (no records in the current window), waiting, or error. An idle source is not necessarily a broken collector. Missing/unreadable files are retried.

## Detection and incident lifecycle

Default window: 60 seconds. Thresholds are currently code-defined in `monitoring/core.py`:

| Signal | Trigger |
|---|---|
| Application errors | At least 5 app 5xx records and at least 20% of app records for a route |
| Authentication failures | At least 10 app 401/403 records for a route |
| Suspicious requests | At least 3 messages containing selected traversal, SQL, or script patterns |
| WAF blocks | At least 5 blocked WAF records and at least 20% blocked for a route |
| Traffic spike | At least 20 app records, at least 5 in the preceding window, and at least 3× that preceding count |

Signals are grouped by kind and route. First/last seen and status persist. After 120 seconds without a qualifying signal's last evidence, an incident resolves. A new qualifying burst reopens it. Request patterns and thresholds are heuristics, not validated attack classifiers; load tests, client mistakes and normal campaigns can trigger them. Automated resolution means the signal went quiet, not that the underlying problem was fixed.

## Optional AI worker

`--model` enables local Ollama inference. `--documents` accepts a JSON array of `{id,title,text}` service documents and enables BM25 RAG. No paid fallback or action tools exist.

A separate single AI worker runs on a new incident, reopening, or a doubling of the stored trigger count. Attempts have a 60-second per-incident cooldown. Failed calls expose an error and retry after cooldown. Unchanged completed incidents do not repeatedly invoke the model. Pending revisions are serialized; obsolete results cannot overwrite newer revisions. AI can lag under load; the collector does not wait for inference.

The UI shows AI state, errors, and whether an assessment belongs to an earlier revision. Output schemas and citation IDs are checked, but valid citations do not guarantee correct interpretation. Raw evidence is untrusted and can contain prompt injection. Nothing executes model-recommended commands. Hardware/energy costs remain even though no paid API is required.

Local logs and reports may contain personal data or secrets; automatic redaction is not implemented. Keep the database local and review exported evidence before sharing.

## Verification

`pytest` covers ingestion, restart checkpoints, partial/malformed lines, common rotation, source recovery, incident resolution/reopening, AI cooldown/failure isolation, traffic windows, and read-only API/export behavior. These are engineering regression tests, not real-world detection benchmarks.
