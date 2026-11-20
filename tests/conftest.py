from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from mcp_vet.engine import scan
from mcp_vet.models import Finding, ServerSnapshot, ToolDef

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
SERVERS = EXAMPLES / "servers"


def tool(name: str, description: str = "", params: dict[str, Any] | None = None, **annotations: Any) -> ToolDef:
    schema: dict[str, Any] = {"type": "object", "properties": params or {}}
    return ToolDef(name=name, description=description, input_schema=schema, annotations=annotations)


def server(name: str, *tools: ToolDef) -> ServerSnapshot:
    return ServerSnapshot(name=name, tools=list(tools))


def rule_ids(findings: list[Finding]) -> set[str]:
    return {f.rule_id for f in findings}


def scan_one(*tools: ToolDef) -> list[Finding]:
    return scan([server("s", *tools)])


@pytest.fixture
def python_exe() -> str:
    return sys.executable
