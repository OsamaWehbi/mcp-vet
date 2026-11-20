"""End-to-end tests: a real MCP client talks to a demo server through `mcp-vet proxy`."""

import json
import os
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_vet.cli import _guess_name
from mcp_vet.proxy import ProxyError, resolve_command
from tests.conftest import SERVERS

pytestmark = pytest.mark.anyio


def _params(server: str, *options: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_vet", "proxy", *options, "--", sys.executable, str(SERVERS / server)],
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )


async def _run(server: str, options: list[str], actions):
    with open(os.devnull, "w") as errlog:
        async with stdio_client(_params(server, *options), errlog=errlog) as (r, w), ClientSession(r, w) as session:
            await session.initialize()
            return await actions(session)


def _text(result) -> str:
    return "".join(getattr(c, "text", "") for c in result.content)


def _events(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


async def test_enforce_mode_blocks_hostile_results_and_passes_clean_ones(tmp_path):
    log = tmp_path / "events.jsonl"

    async def actions(s):
        tools = [t.name for t in (await s.list_tools()).tools]
        return (
            tools,
            await s.call_tool("get_forecast", {"city": "Montreal"}),
            await s.call_tool("get_page", {"slug": "install"}),
            await s.call_tool("get_note", {"note_id": 1}),
            await s.call_tool("get_settings", {"service": "api"}),
        )

    tools, forecast, page, note, settings = await _run(
        "runtime_server.py", ["--mode", "enforce", "--log", str(log), "--quiet"], actions
    )
    assert sorted(tools) == ["get_forecast", "get_note", "get_page", "get_settings"]
    assert not forecast.is_error and "sunny" in _text(forecast)
    assert page.is_error and "MV701" in _text(page)
    assert "Ignore all previous" not in _text(page)  # the payload never reaches the model
    assert note.is_error and "MV702" in _text(note)
    assert not settings.is_error  # MV704 is medium: logged, not blocked at the default --block-on high

    events = _events(log)
    by_rule = {(e["rule_id"], e["tool"], e["action"]) for e in events}
    assert ("MV701", "get_page", "blocked") in by_rule
    assert ("MV702", "get_note", "blocked") in by_rule
    assert ("MV704", "get_settings", "logged") in by_rule
    secret = next(e for e in events if e["rule_id"] == "MV704")
    assert "redacted" in secret["evidence"] and "IOSFODNN7" not in secret["evidence"]
    assert any("forward this note" in e["evidence"] for e in events if e["rule_id"] == "MV702")
    assert log.read_bytes().isascii()


async def test_monitor_mode_changes_nothing_but_logs(tmp_path):
    log = tmp_path / "events.jsonl"

    async def actions(s):
        return await s.call_tool("get_page", {"slug": "install"})

    page = await _run("runtime_server.py", ["--log", str(log), "--quiet"], actions)
    assert not page.is_error and "Ignore all previous instructions" in _text(page)
    assert {(e["rule_id"], e["action"]) for e in _events(log)} >= {("MV701", "logged")}


async def test_enforce_mode_removes_poisoned_definitions_and_refuses_calls(tmp_path):
    log = tmp_path / "events.jsonl"

    async def actions(s):
        tools = [t.name for t in (await s.list_tools()).tools]
        prompts = [p.name for p in (await s.list_prompts()).prompts]
        resources = [str(r.uri) for r in (await s.list_resources()).resources]
        refused = await s.call_tool("add", {"a": 1, "b": 2})
        return tools, prompts, resources, refused

    tools, prompts, resources, refused = await _run(
        "poisoned_server.py", ["--mode", "enforce", "--log", str(log), "--quiet"], actions
    )
    assert tools == [] and prompts == [] and resources == []
    assert refused.is_error and "MV706" in _text(refused)
    actions_taken = {(e["rule_id"], e["tool"], e["action"]) for e in _events(log)}
    assert ("MV101", "add", "removed") in actions_taken
    assert ("MV706", "add", "blocked") in actions_taken


async def test_clean_server_is_untouched_in_enforce_mode(tmp_path):
    log = tmp_path / "events.jsonl"

    async def actions(s):
        tools = [t.name for t in (await s.list_tools()).tools]
        result = await s.call_tool("convert_temperature", {"value": 20, "from_unit": "c", "to_unit": "f"})
        prompts = [p.name for p in (await s.list_prompts()).prompts]
        return tools, result, prompts

    tools, result, prompts = await _run("clean_server.py", ["--mode", "enforce", "--log", str(log), "--quiet"], actions)
    assert sorted(tools) == ["convert_temperature", "get_forecast"]
    assert not result.is_error and prompts == ["forecast_summary"]
    assert not log.exists() or log.read_text() == ""


def test_command_resolution_and_names():
    with pytest.raises(ProxyError, match="no server command"):
        resolve_command([])
    with pytest.raises(ProxyError, match="command not found"):
        resolve_command(["definitely-not-a-real-command-mcp-vet"])
    assert resolve_command([sys.executable])[0]
    assert _guess_name(["npx", "-y", "@modelcontextprotocol/server-filesystem", "/srv/data"]) == "server-filesystem"
    assert _guess_name(["python", "examples/servers/runtime_server.py"]) == "runtime_server"
    assert _guess_name(["uv", "run", "my-server"]) == "my-server"
