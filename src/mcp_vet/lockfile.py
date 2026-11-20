"""Pin tool definitions and detect silent changes (rug pulls)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_vet import __version__
from mcp_vet.models import Finding, ServerSnapshot
from mcp_vet.rules.registry import RULES

LOCK_VERSION = 1


class LockError(Exception):
    pass


def build_lock(servers: list[ServerSnapshot]) -> dict[str, Any]:
    return {
        "version": LOCK_VERSION,
        "generator": f"mcp-vet {__version__}",
        "created": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "servers": {s.name: {t.name: t.fingerprint() for t in sorted(s.tools, key=lambda t: t.name)} for s in servers},
    }


def read_lock(path: str | Path) -> dict[str, dict[str, str]]:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LockError(f"{p}: lockfile not found (create it with --update-lock)") from exc
    except json.JSONDecodeError as exc:
        raise LockError(f"{p}: invalid JSON") from exc
    if not isinstance(data, dict) or data.get("version") != LOCK_VERSION or not isinstance(data.get("servers"), dict):
        raise LockError(f"{p}: unsupported lockfile format")
    return data["servers"]


def write_lock(
    path: str | Path, servers: list[ServerSnapshot], existing: dict[str, dict[str, str]] | None = None
) -> None:
    """Write pins for the scanned servers, keeping pins for servers not scanned this time."""
    lock = build_lock(servers)
    if existing:
        merged = dict(existing)
        merged.update(lock["servers"])
        lock["servers"] = dict(sorted(merged.items()))
    Path(path).write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")


def check(servers: list[ServerSnapshot], pins: dict[str, dict[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for server in servers:
        pinned = pins.get(server.name)
        if pinned is None:
            findings.append(RULES["MV404"].finding(server.name, None, None, "no pins recorded for this server"))
            continue
        current = {t.name: t.fingerprint() for t in server.tools}
        for name, digest in sorted(current.items()):
            if name not in pinned:
                findings.append(RULES["MV402"].finding(server.name, name, None, f"sha256 {digest[:12]}"))
            elif pinned[name] != digest:
                findings.append(
                    RULES["MV401"].finding(server.name, name, None, f"pinned {pinned[name][:12]}, now {digest[:12]}")
                )
        for name in sorted(set(pinned) - set(current)):
            findings.append(RULES["MV403"].finding(server.name, name, None, f"pinned {pinned[name][:12]}"))
    return findings
