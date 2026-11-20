"""The test harness: every vulnerable demo server must trigger its checks, and the clean one none.

The offline tests use the committed snapshot. The live tests launch each demo server over
stdio with the real MCP SDK and confirm the snapshot still matches what the servers advertise.
"""

import json

import pytest

from mcp_vet.engine import scan
from mcp_vet.loaders import connect_stdio, load_tools_file
from tests.conftest import EXAMPLES, SERVERS, rule_ids

SNAPSHOT = EXAMPLES / "demo-snapshot.json"

EXPECTED = {
    "poisoned": {"MV101", "MV102", "MV103", "MV104", "MV105"},
    "overprivileged": {"MV102", "MV201", "MV202", "MV203", "MV205", "MV206", "MV301", "MV302", "MV303"},
    "shadowing": {"MV101", "MV502", "MV503"},
    "mail": set(),
    "clean": set(),
}


@pytest.fixture(scope="module")
def findings():
    return scan(load_tools_file(SNAPSHOT))


@pytest.mark.parametrize(("name", "expected"), EXPECTED.items())
def test_each_demo_server_triggers_exactly_its_checks(findings, name, expected):
    got = rule_ids([f for f in findings if f.server == name])
    assert got == expected


def test_cross_server_exfiltration_is_reported(findings):
    assert any(f.rule_id == "MV204" for f in findings)


def test_clean_server_alone_has_no_findings():
    clean = [s for s in load_tools_file(SNAPSHOT) if s.name == "clean"]
    assert scan(clean) == []


@pytest.mark.anyio
@pytest.mark.parametrize("name", list(EXPECTED))
async def test_live_server_matches_committed_snapshot(name, python_exe):
    live = await connect_stdio(name, python_exe, [str(SERVERS / f"{name}_server.py")], timeout=60)
    committed = {s.name: s for s in load_tools_file(SNAPSHOT)}[name]
    assert {t.name: t.fingerprint() for t in live.tools} == {t.name: t.fingerprint() for t in committed.tools}, (
        "examples/demo-snapshot.json is out of date; regenerate it as described in CONTRIBUTING.md"
    )


def test_snapshot_file_is_ascii_only():
    # Hidden characters must stay escaped so reviewers can see them.
    raw = SNAPSHOT.read_bytes()
    assert raw.isascii()
    json.loads(raw)


def test_repository_text_files_are_ascii_only():
    """Guard against Trojan Source: hidden characters must always be written as escapes."""
    root = SNAPSHOT.parent.parent
    suffixes = {".py", ".json", ".md", ".yml", ".yaml", ".toml", ".txt"}
    skip = {".git", ".venv", "venv", ".ruff_cache", ".pytest_cache", "__pycache__", "build", "dist"}
    offenders = []
    for path in root.rglob("*"):
        if path.suffix in suffixes and path.is_file() and not skip & set(path.relative_to(root).parts):
            data = path.read_bytes()
            if not data.isascii() or any(b < 32 and b not in (9, 10, 13) for b in data):
                offenders.append(str(path.relative_to(root)))
    assert offenders == []
