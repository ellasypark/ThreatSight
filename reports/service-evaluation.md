# Local model development run

Run on September 10, 2026 (America/New_York), Apple M4, 16 GiB RAM, Python 3.13.15, Ollama 0.31.1. Model: `llama3.2:3b`, locally listed ID `a80c4f17acd5` (2.0 GB).

**The small local model did not outperform the conservative rules baseline.** This is a measured limitation, not a production-quality claim.

| Method | Correct / 6 | Abstentions / 6 | Correct among answered | p50 | p95 | Mean input tokens |
|---|---:|---:|---:|---:|---:|---:|
| Rules | 4 | 5 | 1 / 1 | <1 ms | <1 ms | 0 |
| Logs-only LLM | 2 | 2 | 1 / 4 | 2.73 s | 3.20 s | 660.3 |
| LLM + service RAG | 2 | 2 | 1 / 4 | 2.25 s | 4.33 s | 707.8 |

All calls completed. No paid API was used. Local compute/energy costs were not measured. Retrieval Recall@3 was 1.0 across the four cases with relevant-document labels; these are very small corpora, so this is not a retrieval benchmark.

A first development run exposed invented evidence IDs. Constraining citation IDs in the model's output schema eliminated nonexistent references in the recorded run, but did not establish semantic correctness or improve classification. Do not confuse valid references with supported conclusions.

The dataset contains six synthetic development scenarios and three expected abstentions. This makes overall accuracy strongly dependent on abstention behavior. The rules baseline is intentionally conservative; it only classified one case. LLM false alarms remain a clear improvement target. The fixtures were not held out, there are no confidence intervals, and this run does not establish superiority of any method on real traffic.

The raw JSON preserves each result, source evidence, counts, and hashes. Unsupported-claim and prompt-injection success rates remain unmeasured. The included injection case is a regression scenario, not a complete security evaluation.

Next: independently labeled held-out cases, a stronger local-model comparison under an explicit memory budget, and manual claim-support annotations. Keep the free rules workflow as the default until the AI branch demonstrates value.
