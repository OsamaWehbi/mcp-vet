"""Pin tool, prompt and resource definitions and detect silent changes (rug pulls).

Lockfile version 2 stores one section per kind of definition:

    {"version": 2, "servers": {"github": {"tools": {...}, "prompts": {...},
                                          "resources": {...}, "templates": {...}}}}

Version 1 lockfiles (tools only, `{"servers": {"github": {"tool": "sha256"}}}`) are still read.
Only their tools are checked, so upgrading does not flag every prompt and resource as new.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_vet import __version__
from mcp_vet.models import Finding, ServerSnapshot
from mcp_vet.rules.registry import RULES

LOCK_VERSION = 2
SECTIONS = {"tools": "tool", "prompts": "prompt", "resources": "resource", "templates": "template"}

# server name -> section -> item name -> sha256. A missing section means "not tracked".
Pins = dict[str, dict[str, dict[str, str]]]


class LockError(Exception):
    pass


def _sections(server: ServerSnapshot) -> dict[str, dict[str, str]]:
    return {
        "tools": {t.name: t.fingerprint() for t in sorted(server.tools, key=lambda t: t.name)},
        "prompts": {p.name: p.fingerprint() for p in sorted(server.prompts, key=lambda p: p.name)},
        "resources": {r.uri: r.fingerprint() for r in sorted(server.resources, key=lambda r: r.uri) if not r.template},
        "templates": {r.uri: r.fingerprint() for r in sorted(server.resources, key=lambda r: r.uri) if r.template},
    }


def build_lock(servers: list[ServerSnapshot]) -> dict[str, Any]:
    return {
        "version": LOCK_VERSION,
        "generator": f"mcp-vet {__version__}",
        "created": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "servers": {s.name: _sections(s) for s in servers},
    }


def _valid_map(value: Any) -> bool:
    return isinstance(value, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in value.items())


def read_lock(path: str | Path) -> Pins:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LockError(f"{p}: lockfile not found (create it with --update-lock)") from exc
    except json.JSONDecodeError as exc:
        raise LockError(f"{p}: invalid JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("servers"), dict):
        raise LockError(f"{p}: unsupported lockfile format")
    version = data.get("version")
    if version not in (1, LOCK_VERSION):
        raise LockError(f"{p}: unsupported lockfile version {version!r}")
    pins: Pins = {}
    for name, entry in data["servers"].items():
        if version == 1 and _valid_map(entry):
            pins[name] = {"tools": dict(entry)}
        elif (
            version == 2 and isinstance(entry, dict) and all(k in SECTIONS and _valid_map(v) for k, v in entry.items())
        ):
            pins[name] = {k: dict(v) for k, v in entry.items()}
        else:
            raise LockError(f"{p}: unsupported lockfile format")
    return pins


def write_lock(path: str | Path, servers: list[ServerSnapshot], existing: Pins | None = None) -> None:
    """Write pins for the scanned servers, keeping pins for servers not scanned this time."""
    lock = build_lock(servers)
    if existing:
        merged = dict(existing)
        merged.update(lock["servers"])
        lock["servers"] = dict(sorted(merged.items()))
    Path(path).write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")


def check(servers: list[ServerSnapshot], pins: Pins) -> list[Finding]:
    findings: list[Finding] = []
    for server in servers:
        pinned_server = pins.get(server.name)
        if pinned_server is None:
            findings.append(RULES["MV404"].finding(server.name, None, None, "no pins recorded for this server"))
            continue
        current_server = _sections(server)
        for section, kind in SECTIONS.items():
            pinned = pinned_server.get(section)
            if pinned is None:
                continue  # not tracked, e.g. prompts in a version 1 lockfile
            current = current_server[section]
            for name, digest in sorted(current.items()):
                if name not in pinned:
                    findings.append(RULES["MV402"].finding(server.name, name, None, f"sha256 {digest[:12]}", kind=kind))
                elif pinned[name] != digest:
                    findings.append(
                        RULES["MV401"].finding(
                            server.name, name, None, f"pinned {pinned[name][:12]}, now {digest[:12]}", kind=kind
                        )
                    )
            for name in sorted(set(pinned) - set(current)):
                findings.append(
                    RULES["MV403"].finding(server.name, name, None, f"pinned {pinned[name][:12]}", kind=kind)
                )
    return findings
