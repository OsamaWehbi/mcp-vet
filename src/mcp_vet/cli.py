"""Command-line interface."""

from __future__ import annotations

import json
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import anyio
import typer
from rich.console import Console
from rich.table import Table

from mcp_vet import __version__, lockfile, report
from mcp_vet.engine import scan as run_scan
from mcp_vet.loaders import (
    LoadError,
    load_client_config,
    load_http_url,
    load_stdio_command,
    load_tools_file,
    snapshot_document,
)
from mcp_vet.models import ServerSnapshot, Severity
from mcp_vet.proxy import ProxyError, resolve_command, run_proxy
from mcp_vet.rules import RULES
from mcp_vet.runtime import Event, Mode, RuntimeInspector

app = typer.Typer(
    name="mcp-vet",
    help="Security scanner for Model Context Protocol (MCP) servers.",
    no_args_is_help=True,
    add_completion=False,
)
err = Console(stderr=True)

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


class OutputFormat(StrEnum):
    table = "table"
    json = "json"
    sarif = "sarif"
    markdown = "markdown"


def _severity(value: str) -> Severity | None:
    if value.lower() == "none":
        return None
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _split(values: list[str] | None) -> list[str]:
    return [v.strip() for item in values or [] for v in item.split(",") if v.strip()]


@app.command()
def scan(
    files: Annotated[
        list[Path] | None,
        typer.Argument(
            help="Offline inputs: saved tools/list results or mcp-vet snapshots (JSON). Nothing is executed."
        ),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="MCP client config (mcpServers). Starts or connects to each server."),
    ] = None,
    stdio: Annotated[
        list[str] | None, typer.Option("--stdio", help='Launch a stdio server, e.g. "npx -y some-server".')
    ] = None,
    http: Annotated[list[str] | None, typer.Option("--http", help="Connect to a Streamable HTTP server URL.")] = None,
    server: Annotated[
        list[str] | None, typer.Option("--server", "-s", help="Only scan these server names from --config.")
    ] = None,
    fmt: Annotated[OutputFormat, typer.Option("--format", "-f", help="Output format.")] = OutputFormat.table,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report to a file instead of stdout.")
    ] = None,
    fail_on: Annotated[
        str, typer.Option(help="Exit 1 when a finding is at or above this severity (or 'none').")
    ] = "high",
    min_severity: Annotated[str, typer.Option(help="Hide findings below this severity.")] = "info",
    ignore: Annotated[list[str] | None, typer.Option("--ignore", help="Rule IDs to skip, e.g. MV105,MV303.")] = None,
    lock: Annotated[
        Path | None, typer.Option("--lock", help="Lockfile used to detect changed tools (rug pulls).")
    ] = None,
    update_lock: Annotated[bool, typer.Option("--update-lock", help="Write current tool pins to --lock.")] = False,
    save_snapshot: Annotated[
        Path | None, typer.Option("--save-snapshot", help="Save fetched tool definitions for offline re-scans.")
    ] = None,
    timeout: Annotated[float, typer.Option(help="Seconds to wait for each live server.")] = 30.0,
    summary: Annotated[
        Path | None, typer.Option("--summary", help="Also append a Markdown summary here (e.g. $GITHUB_STEP_SUMMARY).")
    ] = None,
) -> None:
    """Scan MCP servers for tool poisoning, over-permission, schema weaknesses, rug pulls and shadowing."""
    if not (files or config or stdio or http):
        err.print("[red]error:[/] give at least one input file, --config, --stdio or --http")
        raise typer.Exit(EXIT_ERROR)
    if update_lock and not lock:
        err.print("[red]error:[/] --update-lock needs --lock PATH")
        raise typer.Exit(EXIT_ERROR)
    threshold = _severity(fail_on)
    floor = _severity(min_severity) or Severity.INFO

    servers: list[ServerSnapshot] = []
    errors: list[str] = []
    for f in files or []:
        try:
            servers.extend(load_tools_file(f))
        except LoadError as exc:
            errors.append(str(exc))
    if config:
        try:
            snaps, errs = load_client_config(config, timeout=timeout, only=set(_split(server)) or None)
            servers.extend(snaps)
            errors.extend(errs)
        except LoadError as exc:
            errors.append(str(exc))
    for cmd in stdio or []:
        try:
            servers.append(load_stdio_command(cmd, timeout=timeout))
        except LoadError as exc:
            errors.append(str(exc))
    for url in http or []:
        try:
            servers.append(load_http_url(url, timeout=timeout))
        except LoadError as exc:
            errors.append(str(exc))

    for e in errors:
        err.print(f"[red]error:[/] {e}")
    if not servers:
        raise typer.Exit(EXIT_ERROR)

    pins = None
    if lock and not update_lock:
        try:
            pins = lockfile.read_lock(lock)
        except lockfile.LockError as exc:
            err.print(f"[red]error:[/] {exc}")
            raise typer.Exit(EXIT_ERROR) from exc

    findings = run_scan(servers, pins=pins, ignore=_split(ignore), min_severity=floor)

    if update_lock and lock:
        existing = None
        if lock.exists():
            try:
                existing = lockfile.read_lock(lock)
            except lockfile.LockError:
                existing = None
        lockfile.write_lock(lock, servers, existing)
        pinned = sum(len(s.tools) + len(s.prompts) + len(s.resources) for s in servers)
        err.print(f"pinned {pinned} definition(s) to {lock}")
    if save_snapshot:
        # ASCII-escaped so hidden characters stay visible in the saved file and in code review.
        save_snapshot.write_text(json.dumps(snapshot_document(servers), indent=2) + "\n", encoding="utf-8")

    artifact = (
        str(files[0]).replace("\\", "/")
        if files and len(files) == 1
        else (str(config).replace("\\", "/") if config else None)
    )
    if fmt is OutputFormat.table:
        if output:
            with output.open("w", encoding="utf-8") as fh:
                report.render_table(findings, servers, Console(file=fh, width=140, no_color=True))
        else:
            report.render_table(findings, servers, Console())
    else:
        text = {
            OutputFormat.json: lambda: report.to_json(findings, servers),
            OutputFormat.sarif: lambda: report.to_sarif(findings, servers, artifact),
            OutputFormat.markdown: lambda: report.to_markdown(findings, servers),
        }[fmt]()
        if output:
            output.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
        else:
            sys.stdout.write(text if text.endswith("\n") else text + "\n")
    if summary:
        with summary.open("a", encoding="utf-8") as fh:
            fh.write(report.to_markdown(findings, servers))

    if errors:
        raise typer.Exit(EXIT_ERROR)
    if threshold is not None and any(f.severity >= threshold for f in findings):
        raise typer.Exit(EXIT_FINDINGS)


LAUNCHERS = {"python", "python3", "py", "node", "npx", "uv", "uvx", "run", "bunx", "deno", "pipx", "docker"}


def _guess_name(command: list[str]) -> str:
    """'npx -y @scope/server-files /tmp' -> 'server-files'; 'python demo_server.py' -> 'demo_server'."""
    for arg in command:
        if arg.startswith("-"):
            continue
        stem = Path(arg.replace("\\", "/").rstrip("/").split("/")[-1]).stem
        if stem.lower() not in LAUNCHERS:
            return stem or "server"
    return Path(command[0]).stem if command else "server"


@app.command(context_settings={"allow_interspersed_args": False})
def proxy(
    command: Annotated[
        list[str],
        typer.Argument(
            help="The server command and its arguments. Put it after -- (or after all options).",
            metavar="-- COMMAND [ARGS]...",
        ),
    ],
    mode: Annotated[
        Mode, typer.Option(help="monitor logs findings and changes nothing; enforce also blocks them.")
    ] = Mode.monitor,
    block_on: Annotated[str, typer.Option(help="In enforce mode, block findings at or above this severity.")] = "high",
    log: Annotated[Path | None, typer.Option(help="Append every finding to this JSON Lines file.")] = None,
    name: Annotated[
        str | None, typer.Option(help="Server name for findings and lockfile lookups (default: from the command).")
    ] = None,
    lock: Annotated[
        Path | None, typer.Option(help="Lockfile to compare advertised definitions against (rug pulls).")
    ] = None,
    ignore: Annotated[list[str] | None, typer.Option("--ignore", help="Rule IDs to skip, e.g. MV704.")] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Do not print findings to stderr.")] = False,
) -> None:
    """Run a stdio MCP server behind mcp-vet and check its lists and results while an agent uses it.

    Use it in place of the server command in your MCP client config:

        mcp-vet proxy --mode enforce --log mcp-vet.jsonl -- npx -y some-mcp-server
    """
    threshold = _severity(block_on)
    if threshold is None:
        raise typer.BadParameter("use a severity; for no blocking use --mode monitor", param_hint="--block-on")
    pins = None
    if lock:
        try:
            pins = lockfile.read_lock(lock)
        except lockfile.LockError as exc:
            err.print(f"[red]error:[/] {exc}")
            raise typer.Exit(EXIT_ERROR) from exc
    try:
        resolved = resolve_command(command)
    except ProxyError as exc:
        err.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    log_file = log.open("a", encoding="utf-8") if log else None

    def on_event(event: Event) -> None:
        f = event.finding
        if not quiet:
            evidence = f" - {f.evidence[:160]}" if f.evidence else ""
            err.print(
                f"mcp-vet: [{f.severity}] {f.rule_id} {f.target}: {f.title} ({event.action}){evidence}",
                markup=False,
                highlight=False,
                soft_wrap=True,
            )
        if log_file:
            # ASCII-escaped so hidden characters in evidence stay visible in the log.
            log_file.write(json.dumps(event.to_dict()) + "\n")
            log_file.flush()

    inspector = RuntimeInspector(
        server=name or _guess_name(command),
        mode=mode,
        block_on=threshold,
        pins=pins,
        ignore={r.upper() for r in _split(ignore)},
        on_event=on_event,
    )
    if not quiet:
        err.print(f"mcp-vet {__version__} proxy: {inspector.server} in {mode} mode", markup=False, highlight=False)
    try:
        code = anyio.run(run_proxy, resolved, inspector, sys.stdin.buffer, sys.stdout.buffer)
    except ProxyError as exc:
        err.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc
    finally:
        if log_file:
            log_file.close()
    raise typer.Exit(code)


@app.command()
def rules() -> None:
    """List every rule with its default severity and OWASP category."""
    table = Table(header_style="bold")
    for col in ("Rule", "Severity", "Title", "OWASP"):
        table.add_column(col)
    for rule in RULES.values():
        table.add_row(rule.id, str(rule.severity), rule.title, rule.owasp)
    Console().print(table)


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(f"mcp-vet {__version__}")


def main() -> None:  # pragma: no cover
    # Tool names and evidence can contain any Unicode. Never crash on a legacy console encoding.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
