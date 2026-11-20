import pytest

from mcp_vet.engine import scan
from mcp_vet.rules.permissions import Cap, capabilities, tokens
from tests.conftest import rule_ids, scan_one, server, tool

STR = {"type": "string"}


def test_tokens_split_common_naming_styles():
    assert tokens("readFile") == {"read", "file"}
    assert tokens("run-shell_command.v2") == {"run", "shell", "command", "v2"}


@pytest.mark.parametrize(
    ("name", "params", "cap"),
    [
        ("run_command", {"command": STR}, Cap.EXEC),
        ("execute_python", {"code": STR}, Cap.EXEC),
        ("terminal", {}, Cap.EXEC),
        ("write_file", {"path": STR}, Cap.WRITE),
        ("delete", {"path": STR}, Cap.WRITE),
        ("read_file", {"path": STR}, Cap.READ),
        ("list_directory", {"path": STR}, Cap.READ),
        ("fetch", {"url": STR}, Cap.NETWORK),
        ("post_message", {"channel": STR}, Cap.NETWORK),
        ("get_api_key", {"name": STR}, Cap.SECRETS),
        ("read_secret", {"name": STR}, Cap.SECRETS),
    ],
)
def test_capability_classification(name, params, cap):
    assert cap in capabilities(tool(name, "", params))


@pytest.mark.parametrize(
    "name", ["get_forecast", "create_issue", "search_repositories", "get_key_metrics", "list_events"]
)
def test_ordinary_tools_have_no_dangerous_capability(name):
    caps = capabilities(tool(name, "Does an ordinary thing.", {"query": STR}))
    assert not {Cap.EXEC, Cap.WRITE, Cap.SECRETS} & set(caps)


def test_exec_and_write_findings():
    ids = rule_ids(scan_one(tool("run_command", "", {"command": STR}), tool("write_file", "", {"path": STR})))
    assert {"MV201", "MV202"} <= ids


def test_destructive_hint_counts_as_write():
    assert "MV202" in rule_ids(scan_one(tool("purge", "", {}, destructiveHint=True)))


def test_exfiltration_path_within_one_server():
    findings = scan_one(tool("read_file", "", {"path": STR}), tool("http_post", "", {"url": STR}))
    f = next(f for f in findings if f.rule_id == "MV203")
    assert "read_file" in f.evidence and "http_post" in f.evidence


def test_exfiltration_path_across_servers():
    findings = scan(
        [
            server("files", tool("read_file", "", {"path": STR})),
            server("web", tool("fetch", "", {"url": STR})),
        ]
    )
    ids = rule_ids(findings)
    assert "MV204" in ids and "MV203" not in ids


def test_no_cross_server_finding_for_single_server():
    findings = scan([server("only", tool("read_file", "", {"path": STR}), tool("fetch", "", {"url": STR}))])
    assert "MV204" not in rule_ids(findings)


def test_read_only_hint_on_write_tool_is_flagged():
    findings = scan_one(tool("write_file", "", {"path": STR}, readOnlyHint=True))
    f = next(f for f in findings if f.rule_id == "MV205")
    assert f.location == "annotations.readOnlyHint"


def test_honest_read_only_hint_is_not_flagged():
    assert "MV205" not in rule_ids(scan_one(tool("read_file", "", {"path": STR}, readOnlyHint=True)))


def test_broad_server():
    findings = scan_one(
        tool("run_command", "", {"command": STR}),
        tool("write_file", "", {"path": STR}),
        tool("read_file", "", {"path": STR}),
        tool("fetch", "", {"url": STR}),
    )
    assert "MV206" in rule_ids(findings)
