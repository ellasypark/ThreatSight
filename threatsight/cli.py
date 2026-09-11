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

from .detection.anomaly import detect_anomalies
from .enrichment.attack import get_technique
from .detection.detector import detect_signatures
from .ingest.generate import main as generate_main
from .ingest.parse import parse_file
from .output.report import render

app = typer.Typer(
    help="ThreatSight - WAF/web-log threat analyzer (signature + anomaly + LLM), mapped to MITRE ATT&CK.",
    add_completion=False,
)


@app.command()
def generate() -> None:
    """Generate synthetic sample logs (normal + several attacks)."""
    generate_main()


@app.command()
def corpus(
    base: Path = typer.Option(None, "--base",
                              help="Real access log (combined format) to use as the benign base. "
                                   "Omit to synthesise a realistic base with crawler/monitor FP-traps."),
) -> None:
    """Build a semi-synthetic evaluation corpus: real/realistic benign traffic + injected
    attacks, with ground-truth labels. Writes data/corpus/{access.log,labels.json}."""
    from .ingest.corpus import build_corpus, OUT_LABELS, OUT_LOG

    s = build_corpus(str(base) if base else None)
    typer.secho(f"Wrote {s['events']} lines to {OUT_LOG}  (base: {s['base']})", fg=typer.colors.GREEN)
    typer.echo(f"  {s['attacks']} attack IPs · {s['benign']} benign IPs "
               f"({s['borderline']} borderline crawler/monitor FP-traps)")
    typer.echo(f"  ground truth: {OUT_LABELS}")


@app.command()
def metrics(
    corpus: bool = typer.Option(False, "--corpus",
                                help="Score against data/corpus (real base + injected attacks) "
                                     "instead of the clean synthetic set."),
) -> None:
    """Detection metrics: precision / recall / FP rate on a labelled set."""
    if corpus:
        from .evaluation.metrics import main_corpus

        main_corpus()
    else:
        from .evaluation.metrics import main as metrics_main

        metrics_main()


@app.command()
def emulate() -> None:
    """Purple-team: simulate attacks (incl. an evasive one) and show detection coverage."""
    from .detection import emulate as emu

    emu.main()


@app.command(name="threat-model")
def threat_model_cmd(
    system: str = typer.Option("a public web application behind a WAF", "--system",
                               help="System to threat-model."),
) -> None:
    """AI-assisted threat modeling: the LLM proposes the ATT&CK/ATLAS techniques the system is
    exposed to, marks coverage/gaps, and caches the profile (needs ANTHROPIC_API_KEY)."""
    from .enrichment.threat_model import coverage, generate_threat_model, save_threat_model, summary

    if not os.getenv("ANTHROPIC_API_KEY"):
        typer.secho("Set ANTHROPIC_API_KEY first.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    rows = generate_threat_model(system)
    save_threat_model(rows)
    cov = coverage(threat_rows=rows)
    s = summary(cov)
    typer.echo(f"Threat profile for: {system}")
    typer.echo(f"{s['covered']}/{s['total']} covered · {s['gaps']} gap(s)\n")
    for r in cov:
        typer.echo(f"[{r['status']:7}] {r['framework']:6} {r['technique']:12} {r['name']} ({r['tactic']})")
    typer.echo("\nSaved to data/threat_model.json — the dashboard will use it.")


@app.command(name="llm-scan")
def llm_scan(
    log_path: Path = typer.Argument(Path("data/sample/llm_requests.jsonl"),
                                    help="JSONL of LLM API requests."),
) -> None:
    """Scan LLM request logs for prompt-injection / jailbreak abuse (OWASP-LLM / ATLAS)."""
    from .investigation.llm_abuse import detect_llm_abuse, generate_llm_logs, load_llm_logs

    if not log_path.exists():
        generate_llm_logs(log_path)
        typer.echo(f"(generated sample {log_path})")
    dets = detect_llm_abuse(load_llm_logs(log_path))
    typer.echo(f"{len(dets)} LLM-abuse detection(s):")
    for d in dets:
        typer.echo(f"[{d['severity']}] {d['owasp']} ({d['atlas']}) — {d['ip']}/{d['user']}: {d['matched']}")


@app.command()
def investigate(
    log_path: Path = typer.Argument(..., help="Path to a web/WAF access log to investigate."),
    model: str = typer.Option("claude-sonnet-4-6", "--model", help="Anthropic model to use."),
    max_steps: int = typer.Option(8, "--max-steps", help="Max agent tool-use steps."),
) -> None:
    """Multi-agent investigation: triage -> investigation -> justification (needs ANTHROPIC_API_KEY)."""
    from .investigation.orchestrator import investigate as run_investigation

    if not log_path.exists():
        typer.secho(f"Log file not found: {log_path}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    if not os.getenv("ANTHROPIC_API_KEY"):
        typer.secho('Set ANTHROPIC_API_KEY first (use SSL_CERT_FILE for a trusted corporate CA).',
                    fg=typer.colors.RED)
        raise typer.Exit(code=1)

    res = run_investigation(log_path, model=model, max_steps=max_steps)
    typer.secho("== Triage ==", fg=typer.colors.CYAN)
    for i in res["triage"]:
        typer.echo(f"  [P{i['priority']}] {i['ip']} — {i['disposition']}: {i['reason']}")
    typer.secho("\n== Investigation ==", fg=typer.colors.CYAN)
    typer.echo(res["investigation"])
    typer.secho("\n== Assessment ==", fg=typer.colors.CYAN)
    typer.echo(res["assessment"])


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
    from .investigation.ai_analyze import ai_analyze

    if not log_path.exists():
        typer.secho(f"Log file not found: {log_path}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    if not os.getenv("ANTHROPIC_API_KEY"):
        typer.secho('Set ANTHROPIC_API_KEY first.',
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



@app.command(name="service-investigate")
def service_investigate(
    bundle: Path = typer.Argument(..., exists=True, dir_okay=False),
    mode: str = typer.Option("rules", help="rules, llm, or rag; llm/rag use local Ollama"),
    model: str = typer.Option(None, help="Installed Ollama model name"),
    output: Path = typer.Option(None, help="Save .html report or .json result"),
) -> None:
    """Distinguish WAF blocks from application failures using a normalized service bundle."""
    from .service.engine import Bundle, investigate as run
    from .service.report import render as render_service
    try:
        result = run(Bundle.model_validate_json(bundle.read_bytes()), mode, model)
    except Exception as exc:
        typer.echo(f"Investigation failed: {exc}", err=True)
        raise typer.Exit(1)
    text = render_service(result) if output and output.suffix == ".html" else json.dumps(result, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        typer.echo(f"Report saved to {output}")
    else:
        typer.echo(text)


@app.command(name="service-eval")
def service_eval(
    manifest: Path = typer.Argument(..., exists=True, dir_okay=False),
    modes: str = typer.Option("rules", help="Comma-separated rules,llm,rag"),
    model: str = typer.Option(None),
    output: Path = typer.Option(Path("reports/service-evaluation.json")),
) -> None:
    """Compare methods on labeled fixtures; failed model runs remain errors."""
    from .service.evaluate import evaluate
    try:
        result = evaluate(manifest, modes.split(","), model)
    except Exception as exc:
        typer.echo(f"Evaluation failed: {exc}", err=True)
        raise typer.Exit(1)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    typer.echo(json.dumps(result["summary"], indent=2))
    if any(row["errors"] for row in result["summary"].values()):
        raise typer.Exit(1)


@app.command()
def monitor(
    logs: list[Path] = typer.Argument(..., help="nginx combined logs or application JSONL; WAF optional"),
    db: Path = typer.Option(Path("data/monitor.sqlite"), help="Persistent local monitoring state"),
    model: str = typer.Option(None, help="Optional installed Ollama model; AI is off by default"),
    documents: Path = typer.Option(None, help="Optional JSON list of service documents for RAG"),
    interval: float = typer.Option(2, min=0.1, help="Collector polling interval in seconds"),
    port: int = typer.Option(8765, min=1024, max=65535),
) -> None:
    """Continuously monitor local logs and serve a live dashboard on loopback."""
    import uvicorn
    from .monitoring.core import Monitor
    from .monitoring.server import create_app
    try:
        instance = Monitor(logs, db, model=model, documents=documents, interval=interval)
    except Exception as exc:
        typer.echo(f"Monitor setup failed: {exc}", err=True)
        raise typer.Exit(1)
    typer.echo(f"ThreatSight live monitor: http://127.0.0.1:{port} (Ctrl+C to stop)")
    uvicorn.run(create_app(instance), host="127.0.0.1", port=port)


if __name__ == "__main__":
    app()