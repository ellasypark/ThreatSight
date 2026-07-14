"""
Corpus builder tests.

The corpus is only trustworthy if its ground truth is trustworthy: every injected
attacker must be labelled, no attacker IP may collide with a benign IP, and the
realistic base must actually contain the crawler/monitor 'FP traps' that make the
false-positive numbers meaningful. These tests pin all three.
"""

from __future__ import annotations

import json

from threatsight.ingest.corpus import build_corpus
from threatsight.evaluation.metrics import evaluate_corpus


def test_corpus_labels_are_consistent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    summary = build_corpus()  # synthetic realistic base

    labels = json.loads((tmp_path / "data/corpus/labels.json").read_text())
    mal = set(labels["malicious"])
    benign = set(labels["benign_ips"])

    # every attacker is labelled with a technique, and none is also 'benign'
    assert len(mal) == summary["attacks"] >= 5
    assert not (mal & benign), "an attacker IP is also labelled benign"
    for meta in labels["malicious"].values():
        assert meta["technique"].startswith("T")
        assert len(meta["window"]) == 2

    # the realistic base must include the crawler/monitor false-positive traps
    assert set(labels["borderline_ips"]), "no borderline FP-traps in the base"


def test_corpus_produces_measurable_signal(tmp_path, monkeypatch):
    """On the realistic corpus the detectors should find real attacks AND real FPs.

    This is the whole point of the corpus vs. the clean set: FP rate > 0.
    """
    monkeypatch.chdir(tmp_path)
    build_corpus()
    r = evaluate_corpus("data/corpus/access.log", "data/corpus/labels.json")

    assert r["overall"]["recall"] > 0.5          # catches most injected attacks
    assert r["overall"]["fp_rate"] > 0.0         # and DOES misfire on realistic noise
    # the false positives should be the hard cases (crawlers/monitors), not humans
    assert r["fp_from_borderline"], "FPs should come from the crawler/monitor traps"


def test_real_base_dropin(tmp_path, monkeypatch):
    """A real combined-format log can be used as the benign base (NASA/Zenodo/nginx)."""
    monkeypatch.chdir(tmp_path)
    real = tmp_path / "real.log"
    real.write_text(
        '199.72.81.55 - - [01/Jul/1995:00:00:01 -0400] "GET /a HTTP/1.0" 200 100 "-" "Mozilla/2.0"\n'
        'host.example.net - - [01/Jul/1995:00:00:06 -0400] "GET /b HTTP/1.0" 200 200 "-" "Mozilla/2.0"\n',
        encoding="utf-8",
    )
    summary = build_corpus(base_path=str(real))
    assert summary["base"].startswith("real:")
    labels = json.loads((tmp_path / "data/corpus/labels.json").read_text())
    # real hosts become the benign negative class; injected attackers stay positive
    assert "199.72.81.55" in labels["benign_ips"]
    assert set(labels["malicious"])