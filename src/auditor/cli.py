from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table

from auditor.engine.models import ScanOptions
from auditor.engine.openapi import OpenApiParser, SpecError
from auditor.engine.scanner import AuditScanner
from auditor.reporting.render import build_report_payload, write_report_files

app = typer.Typer(help="Automated API Security Auditor — defensive OpenAPI scanner")
console = Console()


def read_spec(path: Path) -> OpenApiParser:
    try:
        return OpenApiParser.from_text(path.read_text(encoding="utf-8"))
    except (OSError, SpecError) as exc:
        console.print(f"[red]Unable to load specification:[/red] {exc}")
        raise typer.Exit(2)


def parse_kv(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            raise typer.BadParameter(f"Expected name=value, got: {item}")
        k, v = item.split("=", 1)
        result[k.strip()] = v.strip()
    return result


@app.command()
def inspect(spec: Annotated[Path, typer.Argument(exists=True, readable=True, help="OpenAPI JSON/YAML file")]):
    """Inspect an API specification without sending network traffic."""
    parser = read_spec(spec)
    info = parser.info()
    console.print(Panel.fit(f"[bold]{info['title']}[/bold]\nVersion: {info['version']} · OpenAPI: {info['openapi']} · Operations: {info['operation_count']}", title="Specification"))
    table = Table(show_lines=False)
    table.add_column("Method", style="bold cyan", width=8)
    table.add_column("Path", style="white")
    table.add_column("Auth", width=8)
    table.add_column("Summary")
    for op in parser.operations():
        table.add_row(op.method, op.path, "yes" if op.security_required else "no", op.summary[:70])
    console.print(table)


@app.command()
def scan(
    spec: Annotated[Path, typer.Argument(exists=True, readable=True, help="OpenAPI JSON/YAML file")],
    base_url: Annotated[str, typer.Option("--base-url", help="Authorized target base URL")],
    bearer_token: Annotated[str | None, typer.Option("--bearer-token", envvar="AUDITOR_BEARER_TOKEN")] = None,
    secondary_bearer_token: Annotated[str | None, typer.Option("--secondary-bearer-token", envvar="AUDITOR_SECONDARY_BEARER_TOKEN")] = None,
    header: Annotated[list[str], typer.Option("--header", help="Additional request header name=value; repeatable")] = [],
    allow_host: Annotated[list[str], typer.Option("--allow-host", help="Exact remote hostname; repeatable")] = [],
    alternate_id: Annotated[list[str], typer.Option("--alternate-id", help="Explicit BOLA candidate name=value; repeatable")] = [],
    allow_write_methods: Annotated[bool, typer.Option("--allow-write-methods", help="Opt in to POST/PUT/PATCH/DELETE operations")] = False,
    rps: Annotated[float, typer.Option("--rps", min=0.1, max=10.0)] = 2.0,
    max_requests: Annotated[int, typer.Option("--max-requests", min=1, max=2000)] = 250,
    timeout: Annotated[float, typer.Option("--timeout", min=1.0, max=60.0)] = 10.0,
    verify_tls: Annotated[bool, typer.Option("--verify-tls/--no-verify-tls")] = True,
    ack_authorized: Annotated[bool, typer.Option("--ack-authorized", help="Confirm you own or are explicitly authorized to test the target")] = False,
    output: Annotated[Path, typer.Option("--output", help="JSON report path")] = Path("reports/report.json"),
    html_report: Annotated[Path | None, typer.Option("--html", help="Optional HTML report path")] = None,
):
    """Run a bounded, non-destructive API security audit."""
    if not ack_authorized:
        console.print("[red]Refusing to scan without --ack-authorized.[/red]")
        raise typer.Exit(2)
    parser = read_spec(spec)
    options = ScanOptions(
        base_url=base_url, bearer_token=bearer_token, secondary_bearer_token=secondary_bearer_token,
        extra_headers=parse_kv(header), allowed_hosts=set(allow_host), alternate_ids=parse_kv(alternate_id), allow_write_methods=allow_write_methods,
        requests_per_second=rps, max_requests=max_requests, timeout_seconds=timeout,
        authorization_ack=True, verify_tls=verify_tls,
    )

    async def run():
        with Progress() as progress:
            task = progress.add_task("[cyan]Auditing API…", total=100)
            async def on_progress(percent, summary):
                progress.update(task, completed=percent, description=f"[cyan]Auditing API…[/cyan] {summary.requests_sent} requests")
            scanner = AuditScanner(parser, options, progress=on_progress)
            return await scanner.scan()

    try:
        findings, summary = asyncio.run(run())
    except Exception as exc:
        console.print(f"[red]Scan failed:[/red] {type(exc).__name__}: {exc}")
        raise typer.Exit(1)

    payload = build_report_payload(findings, summary, options, parser.info())
    write_report_files(payload, str(output), str(html_report) if html_report else None)
    console.print(f"\n[bold green]Scan complete[/bold green] — {summary.requests_sent} requests, {len(findings)} findings")
    table = Table(title="Findings")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Endpoint")
    table.add_column("Title")
    for f in findings:
        table.add_row(f.severity.upper(), f.confidence, f"{f.method} {f.endpoint}", f.title)
    console.print(table)
    console.print(f"JSON report: [cyan]{output}[/cyan]")
    if html_report:
        console.print(f"HTML report: [cyan]{html_report}[/cyan]")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    reload: bool = typer.Option(False, "--reload"),
):
    """Run the FastAPI backend used by the web dashboard."""
    uvicorn.run("auditor.api.main:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    app()
