"""Reproducible case-level evaluation; no labels are passed to the model."""
import hashlib
import json
import math
import platform
import statistics
from pathlib import Path

from .engine import Bundle, investigate

LABELS = ("attack_suspected", "false_positive_suspected", "app_error", "insufficient_evidence")


def ratio(n, d):
    return n / d if d else None


def evaluate(manifest: Path, modes: list[str], model: str | None = None) -> dict:
    cases = json.loads(manifest.read_text())
    if not cases or not modes or len(modes) != len(set(modes)):
        raise ValueError("Provide nonempty cases and unique modes")
    if any(mode not in {"rules", "llm", "rag"} for mode in modes):
        raise ValueError("Unknown evaluation mode")
    if any(mode != "rules" for mode in modes) and not model:
        raise ValueError("LLM evaluation requires an installed --model")
    rows, fingerprints = [], {}
    for case in cases:
        if case["expected"] not in LABELS:
            raise ValueError("Unknown expected disposition")
        path = (manifest.parent / case["file"]).resolve()
        if not path.is_relative_to(manifest.parent.resolve()):
            raise ValueError("Fixture must be inside manifest directory")
        raw = path.read_bytes()
        fingerprints[case["file"]] = hashlib.sha256(raw).hexdigest()
        bundle = Bundle.model_validate_json(raw)
        relevant = set(case.get("relevant_documents", []))
        if not relevant.issubset({d.id for d in bundle.documents}):
            raise ValueError("Relevant document missing from fixture")
        for mode in modes:
            try:
                result = investigate(bundle, mode, model)
                rows.append({"case": case["file"], "expected": case["expected"], "mode": mode,
                             "prediction": result["assessment"]["disposition"],
                             "retrieval_recall_at_3": ratio(len(relevant & set(result["retrieved_document_ids"])), len(relevant)) if mode == "rag" else None,
                             "result": result})
            except Exception as exc:
                # A failed call is never silently converted into a correct abstention.
                rows.append({"case": case["file"], "expected": case["expected"], "mode": mode,
                             "prediction": None, "error": type(exc).__name__ + ": " + str(exc)})
    summary = {}
    for mode in modes:
        group = [r for r in rows if r["mode"] == mode]
        valid = [r for r in group if r["prediction"] is not None]
        answered = [r for r in valid if r["prediction"] != "insufficient_evidence"]
        times = sorted(r["result"]["elapsed_seconds"] for r in valid)
        recalls = [r["retrieval_recall_at_3"] for r in valid if r["retrieval_recall_at_3"] is not None]
        per_class = {}
        for label in LABELS:
            tp = sum(r["expected"] == label and r["prediction"] == label for r in group)
            per_class[label] = {"precision": ratio(tp, sum(r["prediction"] == label for r in group)),
                                "recall": ratio(tp, sum(r["expected"] == label for r in group))}
        summary[mode] = {"cases": len(group), "errors": len(group)-len(valid),
            "accuracy_including_errors": ratio(sum(r["prediction"] == r["expected"] for r in group), len(group)),
            "abstention_rate": ratio(sum(r["prediction"] == "insufficient_evidence" for r in valid), len(group)),
            "answered_accuracy": ratio(sum(r["prediction"] == r["expected"] for r in answered), len(answered)),
            "per_class": per_class,
            "invalid_citation_claim_rate": ratio(sum(r["result"]["validation"]["invalid_citation_claims"] for r in valid), sum(r["result"]["validation"]["raw_claim_count"] for r in valid)),
            "retrieval_recall_at_3": statistics.mean(recalls) if recalls else None,
            "latency_p50_seconds": statistics.median(times) if times else None,
            "latency_p95_seconds": times[max(0, math.ceil(.95*len(times))-1)] if times else None,
            "mean_prompt_tokens": statistics.mean([r["result"]["usage"]["prompt_tokens"] for r in valid]) if valid and all(r["result"]["usage"]["prompt_tokens"] is not None for r in valid) else None,
            "semantic_unsupported_claim_rate": None,
            "prompt_injection_attack_success_rate": None}
    return {"dataset": "Synthetic development fixtures; not a held-out or production benchmark",
            "environment": {"python": platform.python_version(), "platform": platform.platform(), "machine": platform.machine()},
            "model": model, "fixture_sha256": fingerprints, "summary": summary, "cases": rows,
            "limits": ["Semantic claim support and injection success require separate human annotations; null is unmeasured.",
                       "Latency includes cold local-model loading when applicable; hardware utilization is not measured."]}
