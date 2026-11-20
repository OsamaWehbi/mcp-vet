"""Render findings as a terminal table, JSON, SARIF 2.1.0 or Markdown."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from mcp_vet import __version__
from mcp_vet.engine import summarise
from mcp_vet.models import Finding, ServerSnapshot, Severity
from mcp_vet.rules import RULES

SARIF_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
SECURITY_SEVERITY = {Severity.HIGH: "8.0", Severity.MEDIUM: "5.0", Severity.LOW: "3.0", Severity.INFO: "1.0"}
STYLE = {Severity.HIGH: "bold red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "dim"}
HELP_URI = "https://github.com/OsamaWehbi/mcp-vet/blob/main/docs/rules.md"


def _target(f: Finding) -> str:
    return f"{f.server}/{f.tool}" if f.tool else f.server


def render_table(findings: list[Finding], servers: list[ServerSnapshot], console: Console) -> None:
    # Finding fields are already escaped by Rule.finding; server names in the header are not findings.
    tool_count = sum(len(s.tools) for s in servers)
    console.print(f"[bold]mcp-vet {__version__}[/] scanned {len(servers)} server(s), {tool_count} tool(s)")
    if not findings:
        console.print("[green]No findings.[/]")
        return
    table = Table(show_lines=False, header_style="bold")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Target", overflow="fold")
    table.add_column("Finding", overflow="fold")
    for f in findings:
        detail = f"{escape(f.title)}\n[dim]{escape(f.evidence)}[/]" if f.evidence else escape(f.title)
        if f.location:
            detail += f"\n[dim]at {escape(f.location)}[/]"
        table.add_row(f"[{STYLE[f.severity]}]{f.severity}[/]", f.rule_id, escape(_target(f)), detail)
    console.print(table)
    counts = summarise(findings)
    console.print("  ".join(f"{k}: {v}" for k, v in counts.items()))


def to_json(findings: list[Finding], servers: list[ServerSnapshot]) -> str:
    doc = {
        "tool": "mcp-vet",
        "version": __version__,
        "servers": [{"name": s.name, "source": s.source, "tools": len(s.tools)} for s in servers],
        "summary": summarise(findings),
        "findings": [f.model_dump(mode="json") | {"severity": str(f.severity)} for f in findings],
    }
    return json.dumps(doc, indent=2)


def to_sarif(findings: list[Finding], servers: list[ServerSnapshot], artifact_uri: str | None = None) -> str:
    """SARIF 2.1.0 for GitHub code scanning. Results point at the scanned input file when known."""
    used = sorted({f.rule_id for f in findings})
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    for i, rid in enumerate(used):
        rule = RULES[rid]
        index[rid] = i
        rules.append(
            {
                "id": rid,
                "name": rule.title.replace(" ", ""),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {"text": rule.remediation, "markdown": f"{rule.remediation}\n\nOWASP: {rule.owasp}"},
                "helpUri": f"{HELP_URI}#{rid.lower()}",
                "defaultConfiguration": {"level": SARIF_LEVEL[rule.severity]},
                "properties": {
                    "tags": ["security", "mcp", rule.owasp],
                    "security-severity": SECURITY_SEVERITY[rule.severity],
                },
            }
        )
    results = []
    for f in findings:
        loc_name = _target(f) + (f" ({f.location})" if f.location else "")
        result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": index[f.rule_id],
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}: {loc_name}. {f.evidence}".strip()},
            "partialFingerprints": {"mcpVetTarget/v1": f"{f.rule_id}:{f.server}:{f.tool or ''}:{f.location or ''}"},
            "properties": {"security-severity": SECURITY_SEVERITY[f.severity]},
        }
        location: dict[str, Any] = {"logicalLocations": [{"name": loc_name, "kind": "member"}]}
        if artifact_uri:
            location["physicalLocation"] = {
                "artifactLocation": {"uri": artifact_uri},
                "region": {"startLine": 1},
            }
        result["locations"] = [location]
        results.append(result)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-vet",
                        "version": __version__,
                        "informationUri": "https://github.com/OsamaWehbi/mcp-vet",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("`", "'").replace("\n", " ")


def to_markdown(findings: list[Finding], servers: list[ServerSnapshot]) -> str:
    tool_count = sum(len(s.tools) for s in servers)
    lines = [f"### mcp-vet: {len(servers)} server(s), {tool_count} tool(s)", ""]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"
    counts = summarise(findings)
    lines += [", ".join(f"**{k}**: {v}" for k, v in counts.items()), ""]
    lines += ["| Severity | Rule | Target | Finding |", "| --- | --- | --- | --- |"]
    for f in findings:
        detail = _md(f.title) + (f"<br>`{_md(f.evidence)}`" if f.evidence else "")
        lines.append(f"| {f.severity} | {f.rule_id} | `{_md(_target(f))}` | {detail} |")
    return "\n".join(lines) + "\n"
