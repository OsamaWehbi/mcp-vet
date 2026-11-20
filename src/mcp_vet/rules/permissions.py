"""Over-permission: classify what each tool can do and flag dangerous combinations."""

from __future__ import annotations

import re
from enum import StrEnum

from mcp_vet.models import Finding, ServerSnapshot, ToolDef, top_level_params
from mcp_vet.rules.registry import RULES


class Cap(StrEnum):
    EXEC = "execute"
    WRITE = "write"
    READ = "read"
    NETWORK = "network"
    SECRETS = "secrets"


EXEC_TOKENS = {
    "exec",
    "execute",
    "shell",
    "bash",
    "powershell",
    "pwsh",
    "cmd",
    "command",
    "subprocess",
    "eval",
    "terminal",
    "spawn",
    "sh",
}
EXEC_PAIRS = ({"run", "code"}, {"run", "script"}, {"run", "python"}, {"run", "command"}, {"run", "js"})
EXEC_PHRASES = re.compile(
    r"\b(execute|run)s?\s+(arbitrary|any|shell|system|bash|terminal)\b|\barbitrary\s+(code|commands?)\b|\bshell\s+commands?\b",
    re.I,
)
WRITE_VERBS = {
    "write",
    "delete",
    "remove",
    "rm",
    "unlink",
    "move",
    "mv",
    "rename",
    "edit",
    "overwrite",
    "truncate",
    "chmod",
    "chown",
    "mkdir",
    "append",
    "save",
    "patch",
    "rmdir",
}
READ_VERBS = {
    "read",
    "cat",
    "get",
    "list",
    "ls",
    "open",
    "view",
    "search",
    "find",
    "glob",
    "grep",
    "tree",
    "stat",
    "load",
}
FILE_TOKENS = {
    "file",
    "files",
    "dir",
    "directory",
    "directories",
    "folder",
    "folders",
    "path",
    "paths",
    "fs",
    "filesystem",
    "disk",
}
NETWORK_TOKENS = {
    "fetch",
    "http",
    "https",
    "request",
    "url",
    "uri",
    "webhook",
    "curl",
    "wget",
    "download",
    "upload",
    "post",
    "send",
    "email",
    "mail",
    "smtp",
    "slack",
    "sms",
    "message",
    "publish",
    "browse",
    "navigate",
    "tweet",
    "notify",
}
NETWORK_PARAMS = {
    "url",
    "uri",
    "endpoint",
    "webhook",
    "recipient",
    "recipients",
    "to",
    "email",
    "host",
    "hostname",
    "channel",
}
SECRET_TOKENS = {
    "secret",
    "secrets",
    "token",
    "tokens",
    "password",
    "passwords",
    "passwd",
    "credential",
    "credentials",
    "apikey",
    "keychain",
    "vault",
    "cookie",
    "cookies",
    "ssh",
    "env",
    "dotenv",
}
SECRET_PAIRS = ({"api", "key"}, {"private", "key"}, {"access", "key"})


def tokens(name: str) -> set[str]:
    """Split snake_case, kebab-case, dotted and camelCase identifiers into lowercase tokens."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return {t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t}


def _has_pair(toks: set[str], pairs: tuple[set[str], ...]) -> bool:
    return any(p <= toks for p in pairs)


def _is_path_param(param: str) -> bool:
    return bool(tokens(param) & FILE_TOKENS) or param.lower() in {
        "filename",
        "filepath",
        "dirname",
        "src",
        "dest",
        "destination",
        "source",
    }


def capabilities(tool: ToolDef) -> dict[Cap, str]:
    """Return each detected capability with a short reason."""
    name_toks = tokens(tool.name)
    params = top_level_params(tool)
    param_toks: set[str] = set()
    for p in params:
        param_toks |= tokens(p)
    has_path_param = any(_is_path_param(p) for p in params)
    caps: dict[Cap, str] = {}

    if name_toks & EXEC_TOKENS or _has_pair(name_toks, EXEC_PAIRS):
        caps[Cap.EXEC] = f"name '{tool.name}'"
    elif {"command", "cmd", "script", "shell"} & param_toks and not name_toks & READ_VERBS:
        caps[Cap.EXEC] = "command-like parameter"
    elif EXEC_PHRASES.search(tool.description):
        caps[Cap.EXEC] = "description mentions command execution"

    file_scope = bool(name_toks & FILE_TOKENS) or has_path_param
    if name_toks & WRITE_VERBS and file_scope:
        caps[Cap.WRITE] = f"name '{tool.name}'"
    elif tool.annotations.get("destructiveHint") is True:
        caps[Cap.WRITE] = "declares destructiveHint"

    if name_toks & READ_VERBS and file_scope:
        caps[Cap.READ] = f"name '{tool.name}'"

    if name_toks & NETWORK_TOKENS:
        caps[Cap.NETWORK] = f"name '{tool.name}'"
    elif {p.lower() for p in params} & NETWORK_PARAMS:
        caps[Cap.NETWORK] = "network destination parameter"

    if name_toks & SECRET_TOKENS or _has_pair(name_toks, SECRET_PAIRS):
        caps[Cap.SECRETS] = f"name '{tool.name}'"

    return caps


SOURCES = (Cap.READ, Cap.SECRETS, Cap.EXEC)


def check(servers: list[ServerSnapshot]) -> list[Finding]:
    findings: list[Finding] = []
    client_sources: list[str] = []
    client_sinks: list[str] = []

    for server in servers:
        server_caps: dict[Cap, list[str]] = {}
        for tool in server.tools:
            caps = capabilities(tool)
            for cap in caps:
                server_caps.setdefault(cap, []).append(tool.name)

            if Cap.EXEC in caps:
                findings.append(RULES["MV201"].finding(server.name, tool.name, None, caps[Cap.EXEC]))
            if Cap.WRITE in caps:
                findings.append(RULES["MV202"].finding(server.name, tool.name, None, caps[Cap.WRITE]))

            ann = tool.annotations
            risky = [c.value for c in (Cap.EXEC, Cap.WRITE) if c in caps]
            if Cap.NETWORK in caps and {"send", "post", "upload", "email", "publish", "webhook"} & tokens(tool.name):
                risky.append("send")
            if ann.get("readOnlyHint") is True and risky:
                findings.append(
                    RULES["MV205"].finding(
                        server.name,
                        tool.name,
                        "annotations.readOnlyHint",
                        f"readOnlyHint=true but tool looks like: {', '.join(risky)}",
                    )
                )
            elif ann.get("destructiveHint") is False and Cap.EXEC in caps:
                findings.append(
                    RULES["MV205"].finding(
                        server.name,
                        tool.name,
                        "annotations.destructiveHint",
                        "destructiveHint=false on a command execution tool",
                    )
                )

        sources = sorted({t for c in SOURCES for t in server_caps.get(c, [])})
        sinks = sorted(set(server_caps.get(Cap.NETWORK, [])))
        if sources and sinks and set(sources) != set(sinks):
            findings.append(
                RULES["MV203"].finding(
                    server.name,
                    None,
                    None,
                    f"reads local data or secrets via {', '.join(sources[:5])}; sends via {', '.join(sinks[:5])}",
                )
            )
        if len(server_caps) >= 4:
            findings.append(
                RULES["MV206"].finding(
                    server.name, None, None, "capabilities: " + ", ".join(sorted(c.value for c in server_caps))
                )
            )
        client_sources += [(server.name, t) for t in sources]
        client_sinks += [(server.name, t) for t in sinks]

    src_servers = {s for s, _ in client_sources}
    sink_servers = {s for s, _ in client_sinks}
    pairs = sorted((a, b) for a in src_servers for b in sink_servers if a != b)
    if pairs:

        def _fmt(entries: list[tuple[str, str]], keep: set[str]) -> str:
            return ", ".join(f"{s}/{t}" for s, t in entries if s in keep)[:200]

        src_keep = {a for a, _ in pairs}
        sink_keep = {b for _, b in pairs}
        findings.append(
            RULES["MV204"].finding(
                "(all servers)",
                None,
                None,
                f"read side: {_fmt(client_sources, src_keep)}; send side: {_fmt(client_sinks, sink_keep)}",
            )
        )
    return findings
