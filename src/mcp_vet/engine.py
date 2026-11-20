"""Run every rule over a set of server snapshots."""

from __future__ import annotations

from collections.abc import Iterable

from mcp_vet import lockfile
from mcp_vet.models import Finding, ServerSnapshot, Severity
from mcp_vet.rules import permissions, poisoning, schema, shadowing

CHECKS = (poisoning.check, permissions.check, schema.check, shadowing.check)


def scan(
    servers: list[ServerSnapshot],
    pins: dict[str, dict[str, str]] | None = None,
    ignore: Iterable[str] = (),
    min_severity: Severity = Severity.INFO,
) -> list[Finding]:
    ignored = {r.strip().upper() for r in ignore if r.strip()}
    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check(servers))
    if pins is not None:
        findings.extend(lockfile.check(servers, pins))

    seen: set[tuple[str, str, str | None, str | None, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.server, f.tool, f.location, f.evidence)
        if f.rule_id in ignored or f.severity < min_severity or key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return sorted(unique, key=Finding.sort_key)


def summarise(findings: list[Finding]) -> dict[str, int]:
    counts = {str(s): 0 for s in sorted(Severity, reverse=True)}
    for f in findings:
        counts[str(f.severity)] += 1
    return counts
