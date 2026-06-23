"""
ThreatSight command-line interface.

After install (`pip install .`):
    threatsight generate                       # write sample logs
    threatsight analyze LOG_PATH               # rules: signature + anomaly (fast, free)
    threatsight analyze LOG_PATH --format json
    threatsight ai-analyze LOG_PATH            # LLM analysis via Claude (needs ANTHROPIC_API_KEY)

Before install you can run it as a module:
    python -m threatsight.cli analyze data/sample/access.log
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import typer

from .anomaly import detect_anomalies
from .attack import get_technique
from .detector import detect_signatures
from .generate import main as generate_main
from .parse import parse_file
from .report import render

app = typer.Typer(
    help="ThreatSight - WAF/web-log threat analyzer (signature + anomaly + LLM), mapped to MITRE ATT&CK.",
    add_completion=False,
)


@app.command()
def generate() -> None:
    """Generate synthetic sample logs (normal + several attacks)."""
    generate_main()


@app.command()
def emulate() -> None:
    """Purple-team: simulate attacks (incl. an evasive one) and show detection coverage."""
    from . import emulate as emu

    emu.main()


@app.command()
def analyze(
    log_path: Path = typer.Argument(..., help="Path to a web/WAF access log to analyze."),
    fmt: str = typer.Option("md", "--format", "-f", help="Output format: md or json."),
    output: Path = typer.Option(None, "--output", "-o", help="Write to a file instead of stdout."),
) -> None:
    """Rule-based analysis: signature detections + behavioral anomalies, mapped to ATT&CK."""
    if not log_path.exists():
        typer.secho(f"Log file not found: {log_path}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    events = parse_file(log_path)
    sigs = detect_signatures(events)
    sig_ips = {d["ip"] for d in sigs}
    anom = [a for a in detect_anomalies(events) if a["ip"] not in sig_ips]

    if fmt == "json":
        text = json.dumps(
            {
                "source": str(log_path),
                "events_analysed": len(events),
                "signature_detections": [
                    {**d, "technique_name": get_technique(d["technique"])["name"]} for d in sigs
                ],
                "anomalies": [
                    {**d, "technique_name": get_technique(d["technique"])["name"]} for d in anom
                ],
            },
            default=str,
            indent=2,
        )
    else:
        text = render(sigs, anom, str(log_path), len(events))

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        typer.secho(f"Wrote {fmt} report to {output}", fg=typer.colors.GREEN)
    else:
        typer.echo(text)


@app.command(name="ai-analyze")
def ai_analyze_cmd(
    log_path: Path = typer.Argument(..., help="Path to a web/WAF access log to analyze."),
    model: str = typer.Option("claude-sonnet-4-6", "--model", help="Anthropic model to use."),
    max_lines: int = typer.Option(60, "--max-lines", help="How many log lines to send (cost control)."),
) -> None:
    """LLM analysis via Claude declarative extraction (needs ANTHROPIC_API_KEY)."""
    from .ai_analyze import ai_analyze

    if not log_path.exists():
        typer.secho(f"Log file not found: {log_path}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    if not os.getenv("ANTHROPIC_API_KEY"):
        typer.secho('Set ANTHROPIC_API_KEY first (setx ANTHROPIC_API_KEY "sk-ant-..." then reopen terminal).',
                    fg=typer.colors.RED)
        raise typer.Exit(code=1)

    lines = log_path.read_text(encoding="utf-8").splitlines()[:max_lines]
    result = ai_analyze(lines, model=model)
    typer.echo(f"Claude found {len(result.findings)} finding(s):\n")
    for f in result.findings:
        tag = "ATTACK" if f.is_attack else "benign"
        typer.echo(
            f"[{f.severity}] {tag}: {f.attack_type} ({f.attack_technique_id}) {f.ip} "
            f"conf={f.confidence}\n   {f.explanation}\n   -> {f.recommended_action}"
        )


if __name__ == "__main__":
    app()