"""
RAG over the MITRE ATT&CK knowledge base — local, no external API.

Knowledge base = ATT&CK technique descriptions (from the STIX dataset). On the
first query we build a corpus and index it. Retrieval uses semantic embeddings
(sentence-transformers) if installed, otherwise a built-in TF-IDF cosine
retriever (numpy only) — so it always works offline. The retrieved technique
docs are fed to the investigation agent (the "augment" in RAG).

Optional semantic upgrade:  pip install sentence-transformers
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

import numpy as np

CORPUS_CACHE = Path("data/attack/rag_corpus.json")
TOP_K = 4

# Built-in corpus so RAG works even without the full ATT&CK dataset downloaded.
_FALLBACK_CORPUS = [
    {"id": "T1110.004", "name": "Credential Stuffing", "text": "Adversaries use stolen username and password pairs from breach dumps to log in to many accounts, betting on password reuse."},
    {"id": "T1190", "name": "Exploit Public-Facing Application", "text": "Adversaries exploit weaknesses in internet-facing applications, such as SQL injection or command injection, to gain access."},
    {"id": "T1595.002", "name": "Vulnerability Scanning", "text": "Adversaries scan targets to find vulnerabilities, exposed paths, and misconfigurations before attacking."},
    {"id": "T1499", "name": "Endpoint Denial of Service", "text": "Adversaries flood an endpoint or application with traffic to exhaust resources and cause denial of service."},
    {"id": "AML.T0051", "name": "LLM Prompt Injection", "text": "Adversaries craft prompts that override or bypass an LLM's system instructions to make it misbehave."},
]


def build_corpus(path=CORPUS_CACHE) -> list[dict]:
    """Build (and cache) the ATT&CK technique corpus; fall back to a built-in set."""
    if Path(path).exists():
        return json.loads(Path(path).read_text(encoding="utf-8"))
    corpus = []
    try:
        from .attack import _attack_data
        data = _attack_data()
        for t in data.get_techniques(remove_revoked_deprecated=True):
            tid = next((r.external_id for r in t.external_references if r.source_name == "mitre-attack"), None)
            if tid:
                corpus.append({"id": tid, "name": t.name, "text": (t.get("description", "") or "")[:600]})
    except Exception:
        corpus = list(_FALLBACK_CORPUS)
    if not corpus:
        corpus = list(_FALLBACK_CORPUS)
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(corpus), encoding="utf-8")
    except Exception:
        pass
    return corpus


def _tokens(s: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", s.lower())


@lru_cache(maxsize=1)
def _index():
    """Build the retrieval index once. Returns (mode, corpus, payload)."""
    corpus = build_corpus()
    docs = [f"{c['name']} {c['text']}" for c in corpus]
    try:  # semantic embeddings if available
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("all-MiniLM-L6-v2")
        emb = np.asarray(model.encode(docs, normalize_embeddings=True))
        return ("semantic", corpus, (model, emb))
    except Exception:
        pass
    # TF-IDF fallback (numpy only)
    vocab = sorted({t for d in docs for t in _tokens(d)})
    vidx = {w: i for i, w in enumerate(vocab)}
    n = len(docs)
    df = np.zeros(len(vocab))
    tf = np.zeros((n, len(vocab)))
    for i, d in enumerate(docs):
        toks = _tokens(d)
        for w in toks:
            tf[i, vidx[w]] += 1
        for w in set(toks):
            df[vidx[w]] += 1
    idf = np.log((1 + n) / (1 + df)) + 1
    mat = tf * idf
    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    mat = mat / np.where(norms == 0, 1, norms)
    return ("tfidf", corpus, (vidx, idf, mat))


def retrieve(query: str, top_k: int = TOP_K) -> list[dict]:
    """Return the top-k most relevant ATT&CK technique docs for the query."""
    mode, corpus, payload = _index()
    if mode == "semantic":
        model, emb = payload
        q = np.asarray(model.encode([query], normalize_embeddings=True))[0]
        scores = emb @ q
    else:
        vidx, idf, mat = payload
        q = np.zeros(len(vidx))
        for w in _tokens(query):
            if w in vidx:
                q[vidx[w]] += idf[vidx[w]]
        nrm = np.linalg.norm(q)
        q = q / nrm if nrm else q
        scores = mat @ q
    order = np.argsort(scores)[::-1][:top_k]
    return [{**corpus[i], "score": round(float(scores[i]), 3)} for i in order]