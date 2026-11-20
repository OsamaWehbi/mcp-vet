"""Load tool definitions from files or from live MCP servers.

Two kinds of input are supported:

* **Offline files** (`load_tools_file`): a saved `tools/list` result, a JSON-RPC
  response wrapping one, or a mcp-vet snapshot. Nothing is executed.
* **Live servers** (`load_client_config`, `connect_stdio`, `connect_http`): mcp-vet
  starts or connects to the server and calls `initialize` and `tools/list` only.
  It never calls a tool. Launching a stdio server still runs its code, so only
  scan servers you would be prepared to run.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path
from typing import Any

import anyio

from mcp_vet.models import ServerSnapshot, ToolDef

MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_PAGES = 100
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class LoadError(Exception):
    """Raised when input cannot be read or a server cannot be reached."""


def _read_json(path: Path) -> Any:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise LoadError(f"{path}: file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise LoadError(f"{path}: file not found") from exc
    except json.JSONDecodeError as exc:
        raise LoadError(f"{path}: invalid JSON ({exc.msg} at line {exc.lineno})") from exc


def _tools_from_list(raw: Any, where: str) -> list[ToolDef]:
    if not isinstance(raw, list):
        raise LoadError(f"{where}: 'tools' must be a list")
    tools = []
    for i, item in enumerate(raw):
        try:
            tools.append(ToolDef.from_wire(item))
        except ValueError as exc:
            raise LoadError(f"{where}: tools[{i}]: {exc}") from exc
    return tools


def parse_tools_document(data: Any, default_name: str) -> list[ServerSnapshot]:
    """Parse any supported offline document into server snapshots."""
    if isinstance(data, dict) and isinstance(data.get("result"), dict):
        data = data["result"]  # JSON-RPC response
    if isinstance(data, dict) and "servers" in data:
        servers = data["servers"]
        if not isinstance(servers, list):
            raise LoadError(f"{default_name}: 'servers' must be a list")
        out = []
        for i, entry in enumerate(servers):
            if not isinstance(entry, dict):
                raise LoadError(f"{default_name}: servers[{i}] must be an object")
            name = str(entry.get("name") or f"{default_name}[{i}]")
            out.append(
                ServerSnapshot(
                    name=name,
                    source=str(entry.get("source") or default_name),
                    tools=_tools_from_list(entry.get("tools", []), name),
                )
            )
        return out
    if isinstance(data, dict) and "tools" in data:
        return [
            ServerSnapshot(name=default_name, source=default_name, tools=_tools_from_list(data["tools"], default_name))
        ]
    if isinstance(data, list):
        return [ServerSnapshot(name=default_name, source=default_name, tools=_tools_from_list(data, default_name))]
    raise LoadError(f"{default_name}: expected a tools/list result, a list of tools, or a mcp-vet snapshot")


def load_tools_file(path: str | Path) -> list[ServerSnapshot]:
    p = Path(path)
    return parse_tools_document(_read_json(p), p.stem)


def _expand_env(value: str) -> str:
    return _ENV_REF.sub(lambda m: os.environ.get(m.group(1), ""), value)


async def _list_all_tools(session: Any) -> list[ToolDef]:
    from mcp import types

    tools: list[ToolDef] = []
    cursor: str | None = None
    for _ in range(MAX_PAGES):
        params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
        result = await session.list_tools(params=params)
        for tool in result.tools:
            tools.append(ToolDef.from_wire(tool.model_dump(by_alias=True, exclude_none=True, mode="json")))
        cursor = result.next_cursor
        if not cursor:
            break
    return tools


async def connect_stdio(
    name: str,
    command: str,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    timeout: float = 30.0,
) -> ServerSnapshot:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=command,
        args=list(args or []),
        env={k: _expand_env(str(v)) for k, v in (env or {}).items()} or None,
        cwd=cwd,
    )
    try:
        # Server stderr goes to devnull so it cannot pollute reports.
        with anyio.fail_after(timeout), open(os.devnull, "w") as errlog:
            async with stdio_client(params, errlog=errlog) as (read, write), ClientSession(read, write) as session:
                await session.initialize()
                tools = await _list_all_tools(session)
    except TimeoutError as exc:
        raise LoadError(f"{name}: timed out after {timeout:.0f}s") from exc
    except LoadError:
        raise
    except Exception as exc:
        raise LoadError(f"{name}: could not list tools over stdio ({type(exc).__name__}: {exc})") from exc
    return ServerSnapshot(name=name, source=f"stdio:{command}", tools=tools)


async def connect_http(
    name: str,
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> ServerSnapshot:
    from mcp import ClientSession
    from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

    hdrs = {k: _expand_env(str(v)) for k, v in (headers or {}).items()}
    try:
        with anyio.fail_after(timeout):
            async with (
                create_mcp_http_client(headers=hdrs or None) as http_client,
                streamable_http_client(url, http_client=http_client) as (read, write),
                ClientSession(read, write) as session,
            ):
                await session.initialize()
                tools = await _list_all_tools(session)
    except TimeoutError as exc:
        raise LoadError(f"{name}: timed out after {timeout:.0f}s") from exc
    except Exception as exc:
        raise LoadError(f"{name}: could not list tools over HTTP ({type(exc).__name__}: {exc})") from exc
    return ServerSnapshot(name=name, source=url, tools=tools)


async def _load_config_async(
    path: Path, timeout: float, only: set[str] | None
) -> tuple[list[ServerSnapshot], list[str]]:
    data = _read_json(path)
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if servers is None and isinstance(data, dict):
        servers = data.get("servers")  # VS Code style
    if not isinstance(servers, dict):
        raise LoadError(f"{path}: expected an 'mcpServers' (or 'servers') object")

    snapshots: list[ServerSnapshot] = []
    errors: list[str] = []
    for name, cfg in servers.items():
        if only and name not in only:
            continue
        if not isinstance(cfg, dict):
            errors.append(f"{name}: server entry must be an object")
            continue
        if cfg.get("disabled") is True:
            continue
        try:
            if cfg.get("url"):
                snapshots.append(await connect_http(name, cfg["url"], cfg.get("headers"), timeout))
            elif cfg.get("command"):
                snapshots.append(
                    await connect_stdio(name, cfg["command"], cfg.get("args"), cfg.get("env"), cfg.get("cwd"), timeout)
                )
            else:
                errors.append(f"{name}: entry has neither 'command' nor 'url'")
        except LoadError as exc:
            errors.append(str(exc))
    return snapshots, errors


def load_client_config(
    path: str | Path, timeout: float = 30.0, only: set[str] | None = None
) -> tuple[list[ServerSnapshot], list[str]]:
    """Connect to every server in an MCP client config. Returns snapshots and per-server errors."""
    return anyio.run(_load_config_async, Path(path), timeout, only)


def load_stdio_command(command_line: str, name: str | None = None, timeout: float = 30.0) -> ServerSnapshot:
    parts = shlex.split(command_line, posix=os.name != "nt")
    if not parts:
        raise LoadError("empty --stdio command")
    return anyio.run(connect_stdio, name or Path(parts[0]).stem, parts[0], parts[1:], None, None, timeout)


def load_http_url(url: str, name: str | None = None, timeout: float = 30.0) -> ServerSnapshot:
    return anyio.run(connect_http, name or url, url, None, timeout)


def snapshot_document(snapshots: list[ServerSnapshot]) -> dict[str, Any]:
    """Serialise snapshots so they can be re-scanned offline later."""
    return {
        "servers": [
            {
                "name": s.name,
                "source": s.source,
                "tools": [
                    {
                        k: v
                        for k, v in {
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": t.input_schema,
                            "annotations": t.annotations or None,
                        }.items()
                        if v is not None
                    }
                    for t in s.tools
                ],
            }
            for s in snapshots
        ]
    }
