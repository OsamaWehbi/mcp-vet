"""Shadowing: tools that collide with, impersonate or redirect other servers' tools."""

from __future__ import annotations

import re

from mcp_vet.models import Finding, ServerSnapshot
from mcp_vet.rules.registry import RULES


def _normalise(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _distinctive(name: str) -> bool:
    """Only names that are unlikely to appear as ordinary words count as references."""
    return len(name) >= 4 and (bool(re.search(r"[_\-.]", name)) or bool(re.search(r"[a-z][A-Z]", name)))


def check(servers: list[ServerSnapshot]) -> list[Finding]:
    findings: list[Finding] = []
    owners: dict[str, list[str]] = {}
    normalised: dict[str, set[tuple[str, str]]] = {}
    for server in servers:
        for tool in server.tools:
            owners.setdefault(tool.name, []).append(server.name)
            normalised.setdefault(_normalise(tool.name), set()).add((server.name, tool.name))

    for name, srvs in owners.items():
        unique = sorted(set(srvs))
        if len(unique) > 1:
            for srv in unique:
                others = ", ".join(s for s in unique if s != srv)
                findings.append(RULES["MV501"].finding(srv, name, None, f"also exposed by: {others}"))

    for server in servers:
        for tool in server.tools:
            if not tool.name.isascii():
                bad = "".join(c for c in tool.name if not c.isascii())
                findings.append(
                    RULES["MV503"].finding(server.name, tool.name, "name", f"non-ASCII characters: {bad!r}")
                )
                continue
            twins = {
                (s, n) for s, n in normalised.get(_normalise(tool.name), set()) if s != server.name and n != tool.name
            }
            if twins:
                desc = ", ".join(f"{s}/{n}" for s, n in sorted(twins))
                findings.append(RULES["MV503"].finding(server.name, tool.name, "name", f"near-identical to {desc}"))

    foreign: dict[str, set[str]] = {}
    for server in servers:
        for tool in server.tools:
            if _distinctive(tool.name):
                foreign.setdefault(tool.name, set()).add(server.name)
    patterns = {n: re.compile(rf"(?<![\w-]){re.escape(n)}(?![\w-])") for n in foreign}

    for server in servers:
        own = {t.name for t in server.tools}
        items = [(t.name, "tool", t.text_fields()) for t in server.tools]
        items += [(p.name, "prompt", p.text_fields()) for p in server.prompts]
        items += [(r.uri, r.kind, r.text_fields()) for r in server.resources]
        for name, kind, fields in items:
            text = " ".join(t for _, t in fields)
            for other, srvs in foreign.items():
                if other in own or server.name in srvs:
                    continue
                if patterns[other].search(text):
                    findings.append(
                        RULES["MV502"].finding(
                            server.name,
                            name,
                            "description",
                            f"mentions '{other}' from {', '.join(sorted(srvs))}",
                            kind=kind,
                        )
                    )
    return findings
