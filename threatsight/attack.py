"""
MITRE ATT&CK enrichment from the official STIX dataset.

Instead of hardcoding technique names/tactics, we look them up in the official
ATT&CK Enterprise STIX bundle (downloaded once and cached locally), queried with
the mitreattack-python library.

Add a new detection later? Just reference its technique ID (e.g. "T1190") -- the
name, tactic, link and description are pulled from MITRE automatically.

If the dataset or library isn't available, get_technique() degrades gracefully
(returns the ID + a constructed attack.mitre.org URL) so the tool never crashes.
"""

from __future__ import annotations

import urllib.request
from functools import lru_cache
from pathlib import Path

# Where we cache the official ATT&CK STIX bundle (gitignored - it's ~40 MB).
STIX_PATH = Path("data/attack/enterprise-attack.json")
STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


def _ensure_dataset() -> None:
    """Download the ATT&CK STIX bundle once (~40 MB) and cache it locally."""
    if STIX_PATH.exists():
        return
    STIX_PATH.parent.mkdir(parents=True, exist_ok=True)
    print("Downloading MITRE ATT&CK STIX dataset (one-time, ~40 MB)...")
    urllib.request.urlretrieve(STIX_URL, STIX_PATH)


@lru_cache(maxsize=1)
def _attack_data():
    """Load the ATT&CK dataset once (cached for the whole run)."""
    from mitreattack.stix20 import MitreAttackData

    _ensure_dataset()
    return MitreAttackData(str(STIX_PATH))


@lru_cache(maxsize=256)
def get_technique(attack_id: str) -> dict:
    """Look up an ATT&CK technique by ID -> name, tactic(s), url, description."""
    fallback = {
        "id": attack_id,
        "name": attack_id,
        "tactic": "",
        "url": f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/",
        "description": "",
    }
    try:
        obj = _attack_data().get_object_by_attack_id(attack_id, "attack-pattern")
    except Exception:
        return fallback  # library/dataset unavailable -> graceful fallback
    if obj is None:
        return fallback

    tactics = ", ".join(
        phase.phase_name.replace("-", " ").title()
        for phase in obj.get("kill_chain_phases", [])
    )
    url = next(
        (ref.url for ref in obj.external_references if ref.source_name == "mitre-attack"),
        fallback["url"],
    )
    return {
        "id": attack_id,
        "name": obj.name,
        "tactic": tactics,
        "url": url,
        "description": obj.get("description", ""),
    }