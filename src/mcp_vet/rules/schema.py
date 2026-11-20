"""Schema weaknesses: parameters that accept far more than the tool needs."""

from __future__ import annotations

from typing import Any

from mcp_vet.models import Finding, ServerSnapshot, top_level_params
from mcp_vet.rules.permissions import _is_path_param, tokens
from mcp_vet.rules.registry import RULES

COMMAND_TOKENS = {"command", "cmd", "script", "code", "sql", "shell", "expression", "eval", "program"}
URL_PARAMS = {"url", "uri", "endpoint", "webhook", "webhook_url", "callback_url", "target_url", "link"}


def _is_string(node: dict[str, Any]) -> bool:
    t = node.get("type")
    return t == "string" or (isinstance(t, list) and "string" in t)


def _constrained(node: dict[str, Any]) -> bool:
    return any(k in node for k in ("enum", "const", "pattern"))


def check(servers: list[ServerSnapshot]) -> list[Finding]:
    findings: list[Finding] = []
    for server in servers:
        for tool in server.tools:
            schema = tool.input_schema
            if not schema:
                findings.append(RULES["MV304"].finding(server.name, tool.name, "inputSchema", "no inputSchema"))
            elif schema.get("type", "object") != "object":
                findings.append(
                    RULES["MV304"].finding(server.name, tool.name, "inputSchema", f"type={schema.get('type')!r}")
                )
            for param, node in top_level_params(tool).items():
                if not _is_string(node) or _constrained(node):
                    continue
                loc = f"inputSchema.properties.{param}"
                if _is_path_param(param):
                    findings.append(
                        RULES["MV301"].finding(server.name, tool.name, loc, f"'{param}' accepts any string")
                    )
                elif tokens(param) & COMMAND_TOKENS:
                    findings.append(
                        RULES["MV302"].finding(server.name, tool.name, loc, f"'{param}' accepts any string")
                    )
                elif param.lower() in URL_PARAMS or node.get("format") in ("uri", "url"):
                    findings.append(RULES["MV303"].finding(server.name, tool.name, loc, f"'{param}' accepts any URL"))
    return findings
