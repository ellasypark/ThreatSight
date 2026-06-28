"""
OWASP mapping for detections.

OWASP Top 10 is a small, stable framework (10 categories), so signature
detections use a short authoritative lookup here. Unknown / LLM-detected
findings are classified into OWASP by the LLM automatically (see
ai_analyze.AIFinding.owasp) -- so any traffic gets an OWASP label, hardcoded
only where it's stable and reliable.
"""

from __future__ import annotations

# technique id -> OWASP category (web Top 10, or LLM Top 10 for model attacks)
OWASP_MAP = {
    "T1110.004": "A07:2021 Identification & Authentication Failures",
    "T1190": "A03:2021 Injection",
    "T1059": "A03:2021 Injection",
    "AML.T0051": "OWASP LLM01: Prompt Injection",
}


def owasp_for(technique: str) -> str:
    """Return the OWASP category for a technique id, or '' if not applicable."""
    return OWASP_MAP.get(technique, "")