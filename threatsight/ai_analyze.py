"""
AI log analysis via declarative extraction (the LLM layer) -- powered by Claude.

The deterministic detectors (signature + anomaly) are fast, free and tested, but
only catch patterns we encoded. This layer takes raw log lines, hands them to
Claude, and forces a structured answer that matches a Pydantic schema -- using
Anthropic tool-use ("declare the result shape, the model fills it"). It catches
context-dependent or obfuscated attacks that rules miss, and explains *why*.

Needs an Anthropic API key:  set ANTHROPIC_API_KEY in your environment.

Run from the project root:
    python -m threatsight.ai_analyze data/sample/access.log
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field

DEFAULT_MODEL = "claude-sonnet-4-6"   # override with --model (e.g. claude-haiku-4-5-20251001 for cheaper)
DEFAULT_MAX_LINES = 60                # cost control: lines sent to the model


class AIFinding(BaseModel):
    """One finding the LLM extracts. Declaring this schema IS the instruction."""

    ip: str | None = Field(None, description="source IP if identifiable")
    attack_type: str = Field(
        description="e.g. 'SQL Injection', 'Credential Stuffing', 'Scanning', 'Benign'"
    )
    is_attack: bool
    attack_technique_id: str | None = Field(
        None, description="MITRE ATT&CK technique id if known, e.g. T1190"
    )
    severity: str = Field(description="one of: P1, P2, P3, INFO")
    confidence: float = Field(description="0.0 - 1.0")
    explanation: str = Field(description="one sentence: why this is / isn't an attack")
    recommended_action: str


class AIAnalysis(BaseModel):
    findings: list[AIFinding]


SYSTEM = (
    "You are a detection & response analyst. Analyse the web/WAF access log lines and "
    "identify malicious activity: SQL injection, XSS, credential stuffing, scanning, "
    "command injection, path traversal, and similar. Group by source IP. Map to a MITRE "
    "ATT&CK technique id where you can. Report benign traffic as is_attack=false. "
    "Use the report_findings tool to return your answer."
)


def ai_analyze(log_lines: list[str], model: str = DEFAULT_MODEL) -> AIAnalysis:
    """Send log lines to Claude and get back findings validated against AIAnalysis."""
    import anthropic

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from the environment
    tool = {
        "name": "report_findings",
        "description": "Report the security findings extracted from the log lines.",
        "input_schema": AIAnalysis.model_json_schema(),
    }
    resp = client.messages.create(
        model=model,
        max_tokens=2000,
        system=SYSTEM,
        tools=[tool],
        tool_choice={"type": "tool", "name": "report_findings"},
        messages=[{"role": "user", "content": "Log lines:\n" + "\n".join(log_lines)}],
    )
    for block in resp.content:
        if block.type == "tool_use":
            return AIAnalysis.model_validate(block.input)
    return AIAnalysis(findings=[])


def main() -> None:
    import sys

    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/sample/access.log")
    if not os.getenv("ANTHROPIC_API_KEY"):
        print('Set ANTHROPIC_API_KEY first, e.g.  setx ANTHROPIC_API_KEY "sk-ant-..."  (then reopen terminal)')
        return
    lines = path.read_text(encoding="utf-8").splitlines()[:DEFAULT_MAX_LINES]
    result = ai_analyze(lines)
    print(f"Claude found {len(result.findings)} finding(s):\n")
    for f in result.findings:
        tag = "ATTACK" if f.is_attack else "benign"
        print(
            f"[{f.severity}] {tag}: {f.attack_type} ({f.attack_technique_id}) {f.ip} "
            f"conf={f.confidence}\n   {f.explanation}\n   -> {f.recommended_action}"
        )


if __name__ == "__main__":
    main()