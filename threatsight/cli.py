"""
ThreatSight command-line interface.

After install (`pip install .`):
    threatsight generate                       # write sample logs
    threatsight analyze LOG_PATH               # analyze a log file (markdown report)
    threatsight analyze LOG_PATH --format json
    threatsight analyze LOG_PATH --output report.md

Before install you can run it as a module:
    python -m threatsight.cli analyze data/sample/access.log
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .anomaly import detect_anomalies
from .attack import get_technique
from .detector import detect_credential_stuffing
from .generate import main as generate_main
from .parse import parse_file
from .report import render

app = typer.Typer(
    help="ThreatSight - WAF/web-log threat analyzer (signature + anomaly), mapped to MITRE ATT&CK.",
    add_completion=False,
)


@app.command()
def generate() -> None:
    """Generate synthetic sample logs (normal + credential stuffing + scanner)."""
    generate_main()


@app.command()
def analyze(
    log_path: Path = typer.Argument(..., help="Path to a web/WAF access log to analyze."),
    fmt: str = typer.Option("md", "--format", "-f", help="Output format: md or json."),
    output: Path = typer.Option(None, "--output", "-o", help="Write to a file instead of stdout."),
) -> None:
    """Analyze a log: signature detections + behavioral anomalies, mapped to ATT&CK."""
    if not log_path.exists():
        typer.secho(f"Log file not found: {log_path}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    events = parse_file(log_path)
    sig = detect_credential_stuffing(events)
    sig_ips = {d["ip"] for d in sig}
    anom = [a for a in detect_anomalies(events) if a["ip"] not in sig_ips]

    if fmt == "json":
        text = json.dumps(
            {
                "source": str(log_path),
                "events_analysed": len(events),
                "signature_detections": [
                    {**d, "technique_name": get_technique(d["technique"])["name"]} for d in sig
                ],
                "anomalies": [
                    {**d, "technique_name": get_technique(d["technique"])["name"]} for d in anom
                ],
            },
            default=str,
            indent=2,
        )
    else:
        text = render(sig, anom, str(log_path), len(events))

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        typer.secho(f"Wrote {fmt} report to {output}", fg=typer.colors.GREEN)
    else:
        typer.echo(text)


if __name__ == "__main__":
    app()