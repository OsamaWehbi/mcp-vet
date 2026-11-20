"""Prompts and resources: sensitive resource URIs, open-ended file templates and duplicate prompts."""

from __future__ import annotations

import re
from urllib.parse import unquote

from mcp_vet.models import Finding, ServerSnapshot
from mcp_vet.rules.poisoning import SENSITIVE_PATTERNS
from mcp_vet.rules.registry import RULES

# Only patterns that describe files or credentials make sense inside a URI.
URI_PATTERN_LABELS = {
    "SSH keys",
    "environment files",
    "cloud credentials",
    "MCP or agent config",
    "system password files",
    "private keys",
    "browser or wallet data",
}
_URI_PATTERNS = [(label, p) for label, p in SENSITIVE_PATTERNS if label in URI_PATTERN_LABELS]

# RFC 6570 operators that allow "/" in the expansion: reserved (+), fragment (#) and path segment (/).
_OPEN_EXPANSION = re.compile(r"\{[+#/][^}]*\}")
# file:// templates whose path starts with a variable: file:///{path}, file://{path}, file:///{drive}/...
_NO_FIXED_ROOT = re.compile(r"^file://(/)?\{", re.I)


def _sensitive_uri(uri: str) -> str | None:
    decoded = unquote(uri)
    for label, pattern in _URI_PATTERNS:
        if pattern.search(decoded):
            return label
    return None


def _open_file_template(uri_template: str) -> str | None:
    if not uri_template.lower().startswith("file:"):
        return None
    if _NO_FIXED_ROOT.search(uri_template):
        return "the path starts with a variable, so there is no fixed directory"
    if _OPEN_EXPANSION.search(uri_template):
        return "uses reserved or path expansion, so the variable can contain '/' and '..'"
    return None


def check(servers: list[ServerSnapshot]) -> list[Finding]:
    findings: list[Finding] = []
    for server in servers:
        for res in server.resources:
            label = _sensitive_uri(res.uri)
            if label:
                findings.append(
                    RULES["MV601"].finding(server.name, res.uri, "uri", f"[{label}] {res.uri}", kind=res.kind)
                )
            if res.template:
                reason = _open_file_template(res.uri)
                if reason:
                    findings.append(RULES["MV602"].finding(server.name, res.uri, "uriTemplate", reason, kind=res.kind))

    owners: dict[str, set[str]] = {}
    for server in servers:
        for prompt in server.prompts:
            owners.setdefault(prompt.name, set()).add(server.name)
    for name, srvs in sorted(owners.items()):
        if len(srvs) > 1:
            for srv in sorted(srvs):
                others = ", ".join(s for s in sorted(srvs) if s != srv)
                findings.append(RULES["MV603"].finding(srv, name, None, f"also exposed by: {others}", kind="prompt"))
    return findings
