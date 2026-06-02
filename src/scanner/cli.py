import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner.certification import CertificationPipeline
from scanner.config import Settings
from scanner.monitor import Alerter, MonitorScheduler, MonitorStore
from scanner.pipeline import PipelineOrchestrator
from scanner.policies import PolicyGenerator
from scanner.redteam import AdversarialPageGenerator, ScannerEvaluator
from scanner.reporters import JSONReporter, MarkdownReporter, SimpleReporter
from scanner.reputation import ReputationEngine
from scanner.validator import AgentValidator, BehaviorEvaluator

app = typer.Typer(
    name="pis",
    help="Prompt Injection Scanner — Analyze content for AI agent threats",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    url: str = typer.Argument(None, help="URL to scan"),
    file: str = typer.Option(None, "--file", "-f", help="Local file to scan"),
    paste: str = typer.Option(None, "--paste", "-p", help="Raw text to scan"),
    format: str = typer.Option("rich", "--format", help="Output format: rich, json, markdown, simple"),
    json_output: bool = typer.Option(False, "--json", help="Output scan results as JSON"),
    output: str = typer.Option(None, "--output", "-o", help="Save output to file"),
    ci: bool = typer.Option(False, "--ci", help="CI mode: exit code reflects risk"),
    threshold: str = typer.Option("high", "--threshold", help="CI failure threshold: low, medium, high, critical"),
    llm: bool = typer.Option(False, "--llm", help="Enable LLM classification (requires API key)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    reputation: bool = typer.Option(False, "--reputation", "-r", help="Check and store reputation"),
):
    """Scan a URL, file, or paste for prompt injection."""
    settings = Settings()
    if verbose:
        settings.debug = True

    orchestrator = PipelineOrchestrator(settings=settings)
    rep = ReputationEngine() if reputation else None

    async def run():
        if url:
            report = await orchestrator.scan_url(url)
            if rep:
                rep.record_scan(url, report)
        elif file:
            report = await orchestrator.scan_file(file)
        elif paste:
            report = await orchestrator.scan_paste(paste)
        else:
            console.print("[red]Error:[/] provide a URL, --file, or --paste")
            raise typer.Exit(1)
        return report

    report = asyncio.run(run())

    selected_format = "json" if json_output else format

    if output and not json_output:
        ext = Path(output).suffix.lower()
        format_map = {".json": "json", ".md": "markdown", ".html": "html"}
        selected_format = format_map.get(ext, selected_format)

    reporter_map = {
        "json": JSONReporter(),
        "markdown": MarkdownReporter(),
        "simple": SimpleReporter(),
    }

    if selected_format == "rich":
        _display_rich(report, verbose)
    elif selected_format in reporter_map:
        text = reporter_map[selected_format].render(report)
        if output:
            Path(output).write_text(text)
            console.print(f"[green]Output saved to[/] {output}")
        else:
            print(text)
    else:
        console.print(f"[red]Unknown format:[/] {selected_format}")
        raise typer.Exit(1)

    if reputation and url:
        info = rep.query(url)  # type: ignore[union-attr]
        console.print(f"\n[bold]Reputation:[/] {info['trust_level']} (score: {info['score']:.0f}/100)")

    if ci:
        severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold_val = severity_order.get(threshold, 3)
        cat_val = severity_order.get(report.risk_category, 0)
        if cat_val >= threshold_val:
            console.print(f"[red]CI FAILED:[/] Risk {report.risk_category} >= threshold {threshold}")
            raise typer.Exit(1)
        console.print(f"[green]CI PASSED:[/] Risk {report.risk_category} < threshold {threshold}")


@app.command()
def policies(
    url: str = typer.Argument(..., help="URL to scan and generate policies for"),
    output: str = typer.Option("pis-policies.yaml", "--output", "-o", help="Output file"),
):
    """Scan a URL and generate MCPGuard-compatible policy rules."""
    settings = Settings()
    orchestrator = PipelineOrchestrator(settings=settings)
    gen = PolicyGenerator()

    async def run():
        report = await orchestrator.scan_url(url)
        yaml = gen.to_mcpguard_yaml(report)
        Path(output).write_text(yaml)
        console.print(f"[green]Policies saved to[/] {output}")

    asyncio.run(run())


# ─── Monitor ──────────────────────────────────────────────────────────────


@app.command()
def monitor(
    url: str = typer.Argument(None, help="URL to start monitoring"),
    list_urls: bool = typer.Option(False, "--list", "-l", help="List monitored URLs"),
    interval: float = typer.Option(6.0, "--interval", "-i", help="Scan interval in hours"),
    webhook: str = typer.Option("", "--webhook", "-w", help="Alert webhook URL"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Run as daemon (continuous monitoring)"),
):
    """Monitor URLs for changes in risk posture over time."""
    store = MonitorStore()
    orchestrator = PipelineOrchestrator()
    alerter = Alerter(store)

    if list_urls:
        entries = store.get_urls()
        if not entries:
            console.print("[yellow]No monitored URLs[/]")
            return
        table = Table(title="Monitored URLs")
        table.add_column("URL")
        table.add_column("Score")
        table.add_column("Category")
        table.add_column("Scans")
        table.add_column("Last Scan")
        for e in entries:
            table.add_row(
                e["url"],
                str(e["last_risk_score"]),
                e["last_risk_category"],
                str(e["total_scans"]),
                e.get("last_scan_at", "never"),
            )
        console.print(table)
        return

    if url:
        scheduler = MonitorScheduler(store, orchestrator, alerter)
        scheduler.start()
        console.print(f"[green]Monitoring[/] {url} every {interval}h")
        if daemon:
            console.print("[bold]Running...[/] Press Ctrl+C to stop")
            try:
                asyncio.get_event_loop().run_forever()
            except KeyboardInterrupt:
                scheduler.stop()
        else:
            scheduler.stop()

    else:
        console.print("[red]Provide a URL or --list[/]")


# ─── Proxy ────────────────────────────────────────────────────────────────


@app.command()
def proxy(
    port: int = typer.Option(9090, "--port", "-p", help="Proxy port"),
    mode: str = typer.Option("strip", "--mode", "-m", help="strip/rewrite/block/passthrough"),
):
    """Run the Content Safety Proxy server."""
    from scanner.proxy.server import run_proxy

    console.print(f"[green]Starting Content Safety Proxy on :{port} (mode: {mode})[/]")
    run_proxy(port=port, mode=mode)


# ─── Validate ─────────────────────────────────────────────────────────────


@app.command()
def validate(
    url: str = typer.Argument(..., help="URL to test an agent against"),
    provider: str = typer.Option("browser_use", "--provider", help="Agent provider: browser_use, playwright"),
    scan_first: bool = typer.Option(True, "--scan/--no-scan", help="Run scanner first"),
):
    """Validate a URL by running a real AI agent against it."""
    orchestrator = PipelineOrchestrator()
    validator = AgentValidator(provider=provider)
    evaluator = BehaviorEvaluator()

    async def run():
        if scan_first:
            report = await orchestrator.scan_url(url)
            console.print(f"[bold]Scanner found[/] {report.total_findings} issues (risk: {report.risk_score}/100)")

        console.print(f"[bold]Running agent[/] ({provider}) against {url}...")
        session = await validator.validate(url)
        findings = report.findings if scan_first else []
        result = evaluator.evaluate(session, findings)

        console.print("\n[bold]Agent Vulnerability Report[/]")
        console.print(f"  Steps: {result.total_steps}")
        console.print(f"  Mission success: {result.mission_success}")
        console.print(f"  Injections triggered: {len(result.injections_triggered)}")
        console.print(f"  Injections ignored: {len(result.injections_ignored)}")
        console.print(f"  Vulnerability score: {result.overall_vulnerability_score}/100")

        if result.injections_triggered:
            console.print("\n[red]Triggered injections:[/]")
            for t in result.injections_triggered:
                console.print(f"  • [{t.severity}] {t.injection_text[:80]}")

        return result

    asyncio.run(run())


# ─── Reputation ──────────────────────────────────────────────────────────


@app.command()
def reputation(
    url: str = typer.Argument(None, help="URL to query reputation for"),
    list_threats: bool = typer.Option(False, "--threats", "-t", help="List recent threats"),
):
    """Query or display reputation information."""
    rep = ReputationEngine()

    if list_threats:
        threats = rep.recent_threats()
        if not threats:
            console.print("[green]No recent threats[/]")
            return
        table = Table(title="Recent Threats (24h)")
        table.add_column("Domain")
        table.add_column("Score")
        table.add_column("Level")
        table.add_column("Critical")
        for t in threats:
            table.add_row(t["domain"], f"{t['score']:.0f}", t["trust_level"], str(t["critical_findings"]))
        console.print(table)
        return

    if url:
        info = rep.query(url)
        console.print(f"[bold]Reputation for[/] {url}")
        console.print(f"  Trust level: [bold]{info['trust_level']}[/]")
        console.print(f"  Score: {info['score']:.0f}/100")
        console.print(f"  Total scans: {info['total_scans']}")
        console.print(f"  Total findings: {info['total_findings']}")
    else:
        console.print("[red]Provide a URL or --threats[/]")


# ─── Red Team ────────────────────────────────────────────────────────────


@app.command()
def redteam(
    count: int = typer.Option(5, "--count", "-c", help="Number of adversarial pages to generate"),
    template: str = typer.Option("ecommerce", "--template", "-t", help="Page template: ecommerce, blog"),
):
    """Generate adversarial pages and evaluate the scanner."""
    orchestrator = PipelineOrchestrator()
    generator = AdversarialPageGenerator()
    evaluator = ScannerEvaluator(orchestrator)

    async def run():
        console.print(f"[bold]Generating[/] {count} adversarial pages...")
        pages = [generator.generate(template=template) for _ in range(count)]

        console.print("[bold]Evaluating scanner...[/]")
        result = await evaluator.evaluate(pages)

        console.print("\n[bold]Scanner Evaluation Report[/]")
        console.print(f"  Pages: {result.total_pages}")
        console.print(f"  Injections: {result.total_injections}")
        console.print(f"  Precision: {result.precision:.1%}")
        console.print(f"  Recall: {result.recall:.1%}")
        console.print(f"  F1 Score: {result.f1:.1%}")

        if result.by_category:
            console.print("\n[bold]By Category:[/]")
            for cat, data in result.by_category.items():
                rate = data["tp"] / (data["tp"] + data["fn"]) if (data["tp"] + data["fn"]) > 0 else 0
                console.print(f"  {cat}: {rate:.0%} ({data['tp']}/{data['tp'] + data['fn']})")

        if result.recommendations:
            console.print("\n[yellow]Recommendations:[/]")
            for r in result.recommendations:
                console.print(f"  • {r}")

    asyncio.run(run())


# ─── Certification ───────────────────────────────────────────────────────


@app.command()
def certify(
    url: str = typer.Argument(..., help="URL to certify"),
    email: str = typer.Option("", "--email", "-e", help="Owner email"),
    org: str = typer.Option("", "--org", "-o", help="Organization name"),
    verify: str = typer.Option(None, "--verify", "-v", help="Verify a certificate ID"),
    badge: str = typer.Option(None, "--badge", help="Generate badge HTML for certificate ID"),
):
    """Apply for, verify, or generate badge for AgentSafe certification."""
    orchestrator = PipelineOrchestrator()
    certification = CertificationPipeline(orchestrator)

    async def run():
        if verify:
            info = certification.verify(verify)
            console.print(f"[bold]Certificate {verify}[/]")
            console.print(f"  Valid: {info['valid']}")
            console.print(f"  Status: {info['status']}")
            console.print(f"  URL: {info['url']}")
            console.print(f"  Issued: {info['issued_at']}")
            console.print(f"  Expires: {info['expires_at']}")
            return

        if badge:
            html = certification.badge_html(badge)
            if html:
                console.print(html)
            else:
                console.print("[red]Certificate not found or expired[/]")
            return

        result = await certification.apply(url, email, org)
        console.print("[bold]Certification Applied[/]")
        console.print(f"  Certificate ID: {result.get('certificate_id', 'N/A')}")
        console.print(f"  Status: {result.get('status', 'error')}")
        console.print(f"  Initial risk: {result.get('initial_risk_score', 'N/A')}/100")
        console.print(f"  Monitoring: {result.get('monitoring_period_days', 0)} days")

        if "error" in result:
            console.print(f"[red]{result['error']}[/]")

    asyncio.run(run())


# ─── Web ─────────────────────────────────────────────────────────────────


@app.command()
def web(
    port: int = typer.Option(8000, "--port", "-p", help="Web UI port"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address"),
):
    """Launch the web UI."""
    import uvicorn

    from scanner.api import app as web_app

    console.print(f"[green]Web UI:[/] http://{host}:{port}")
    uvicorn.run(web_app, host=host, port=port)


# ─── Rich Display ────────────────────────────────────────────────────────


def _display_rich(report, verbose: bool = False):
    color_map = {"none": "green", "low": "yellow", "medium": "orange1", "high": "red", "critical": "bold red"}
    color = color_map.get(report.risk_category, "white")
    console.print(
        Panel(
            f"[bold]Risk Score:[/] [{color}]{report.risk_score}/100 ({report.risk_category})[/]\n"
            f"[bold]URL:[/] {report.url}\n"
            f"[bold]Findings:[/] {report.total_findings} | "
            f"[bold]Time:[/] {report.scan_time_ms}ms",
            title="Scan Results",
        )
    )

    if report.summary:
        console.print(Panel(report.summary, title="Summary"))

    if report.findings:
        table = Table(title=f"Findings ({len(report.findings)})")
        table.add_column("Severity", style="bold")
        table.add_column("Category", style="cyan")
        table.add_column("Title")
        table.add_column("Detector")
        if verbose:
            table.add_column("Snippet")

        for f in report.findings:
            sv = f"[red]{f.severity.upper()}[/]" if f.severity in ("critical", "high") else f"[yellow]{f.severity}[/]"
            row = [sv, f.category, f.title[:60], f.detector]
            if verbose:
                row.append(f.snippet[:100])
            table.add_row(*row)

        console.print(table)


def main():
    app()


if __name__ == "__main__":
    main()
