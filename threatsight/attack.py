"""
MITRE ATT&CK enrichment from the official STIX dataset.

Looks up a technique by ATT&CK id and returns the fields a SOC analyst actually
needs: name, tactic, description, the data sources that detect it, and the
mitigations that defend against it -- all pulled from the official ATT&CK STIX
dataset (mitreattack-python), not hardcoded.

If the dataset/library is unavailable, get_technique() degrades gracefully.
"""

from __future__ import annotations

import urllib.request
from functools import lru_cache
from pathlib import Path

STIX_PATH = Path("data/attack/enterprise-attack.json")
STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


def _ensure_dataset() -> None:
    if STIX_PATH.exists():
        return
    STIX_PATH.parent.mkdir(parents=True, exist_ok=True)
    print("Downloading MITRE ATT&CK STIX dataset (one-time, ~40 MB)...")
    urllib.request.urlretrieve(STIX_URL, STIX_PATH)


@lru_cache(maxsize=1)
def _attack_data():
    from mitreattack.stix20 import MitreAttackData

    _ensure_dataset()
    return MitreAttackData(str(STIX_PATH))


@lru_cache(maxsize=256)
def get_technique(attack_id: str) -> dict:
    """Look up a technique -> name, tactic(s), url, description, data_sources, mitigations."""
    fallback = {
        "id": attack_id,
        "name": attack_id,
        "tactic": "",
        "url": f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/",
        "description": "",
        "data_sources": [],
        "mitigations": [],
    }
    try:
        obj = _attack_data().get_object_by_attack_id(attack_id, "attack-pattern")
    except Exception:
        return fallback
    if obj is None:
        return fallback

    tactics = ", ".join(
        p.phase_name.replace("-", " ").title() for p in obj.get("kill_chain_phases", [])
    )
    url = next(
        (r.url for r in obj.external_references if r.source_name == "mitre-attack"),
        fallback["url"],
    )
    description = (obj.get("description", "") or "").split("\n")[0][:240]
    data_sources = list(obj.get("x_mitre_data_sources", []) or [])

    mitigations: list[str] = []
    try:  # related-object lookup; needs the full STIX dataset
        for rel in _attack_data().get_mitigations_mitigating_technique(obj.id):
            m = rel.get("object")
            if m is not None and getattr(m, "name", None):
                mitigations.append(m.name)
    except Exception:
        pass

    return {
        "id": attack_id,
        "name": obj.name,
        "tactic": tactics,
        "url": url,
        "description": description,
        "data_sources": data_sources,
        "mitigations": mitigations[:5],
    }


def attack_coverage(detections: list[dict]) -> list[dict]:
    """Threat-model view: group detections onto the ATT&CK matrix (tactic -> techniques)."""
    by_tactic: dict[str, dict[str, dict]] = {}
    for d in detections:
        tactic = d.get("tactic") or "Unmapped"
        tech = d.get("technique", "?")
        bucket = by_tactic.setdefault(tactic, {})
        entry = bucket.setdefault(tech, {"technique": tech, "name": d.get("name", tech), "count": 0})
        entry["count"] += 1
    return [{"tactic": t, "techniques": list(v.values())} for t, v in by_tactic.items()]