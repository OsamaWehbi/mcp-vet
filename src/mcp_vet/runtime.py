"""Runtime inspection of MCP traffic, used by `mcp-vet proxy`.

`RuntimeInspector` holds no I/O. The proxy feeds it every JSON-RPC message in both directions and
it decides what to forward, what to rewrite and what to log:

* list responses (`tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`) are
  scanned with the static rules, compared with what the server advertised earlier in the session
  (MV705) and, optionally, with a lockfile;
* results (`tools/call`, `prompts/get`, `resources/read`) are checked for injected instructions,
  hidden Unicode, encoded payloads and secrets (MV701 to MV704);
* requests for items the server never listed, or that the proxy removed, are reported (MV706).

In monitor mode traffic is never changed. In enforce mode, items and results with a finding at or above
the blocking severity are removed from lists or replaced with an error, and calls to removed items are
refused without reaching the server.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from mcp_vet.engine import scan
from mcp_vet.lockfile import Pins
from mcp_vet.models import Finding, PromptDef, ResourceDef, ServerSnapshot, Severity, ToolDef, printable
from mcp_vet.rules.poisoning import BASE64_RE, HIDDEN_CHARS, _decode_tags, _snippet, _try_base64, injection_matches
from mcp_vet.rules.registry import RULES

MAX_SCAN_CHARS = 1_000_000  # per string; longer text is scanned up to this length
MAX_BASE64_CHARS = 65_536  # longer base64 runs are data, not hidden instructions

LIST_METHODS = {
    "tools/list": ("tools", "tool"),
    "prompts/list": ("prompts", "prompt"),
    "resources/list": ("resources", "resource"),
    "resources/templates/list": ("resourceTemplates", "template"),
}
LOCK_SECTION = {"tool": "tools", "prompt": "prompts", "resource": "resources", "template": "templates"}

_BIDI_OVERRIDES = {0x202D, 0x202E}
_BIDI = {cp for cp, kind in HIDDEN_CHARS.items() if kind == "BIDI CONTROL"}
_ZERO_WIDTH = {cp for cp, kind in HIDDEN_CHARS.items() if kind == "ZERO WIDTH"} - {0x200D}  # ZWJ joins emoji

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}\b")),
]


class Mode(StrEnum):
    monitor = "monitor"
    enforce = "enforce"


@dataclass
class Event:
    """One finding seen by the proxy, and what was done about it."""

    finding: Finding
    method: str
    action: str  # "logged", "blocked" or "removed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "time": datetime.now(UTC).isoformat(timespec="seconds"),
            "method": self.method,
            "action": self.action,
            **self.finding.model_dump(mode="json"),
            "severity": str(self.finding.severity),
        }


@dataclass
class ClientDecision:
    forward: Any | None  # message to send to the server, or None to drop it
    replies: list[dict[str, Any]] = field(default_factory=list)  # messages to send straight back to the client


@dataclass
class RuntimeInspector:
    server: str
    mode: Mode = Mode.monitor
    block_on: Severity = Severity.HIGH
    pins: Pins | None = None
    ignore: set[str] = field(default_factory=set)
    on_event: Callable[[Event], None] | None = None

    pending: dict[Any, tuple[str, dict[str, Any]]] = field(default_factory=dict)
    seen: dict[str, dict[str, str]] = field(default_factory=dict)  # kind -> item -> fingerprint this session
    listed: dict[str, set[str]] = field(default_factory=dict)  # kind -> items the client was shown
    removed: dict[str, set[str]] = field(default_factory=dict)  # kind -> items removed in enforce mode
    events: list[Event] = field(default_factory=list)
    _reported: set[tuple[str, str, str | None, str | None, str]] = field(default_factory=set)

    # --- Client to server ----------------------------------------------------------------

    def from_client(self, message: Any) -> ClientDecision:
        if isinstance(message, list):  # JSON-RPC batch: decide per request so nothing slips through
            forward: list[Any] = []
            replies: list[dict[str, Any]] = []
            for m in message:
                decision = self.from_client(m)
                if decision.forward is not None:
                    forward.append(decision.forward)
                replies.extend(decision.replies)
            return ClientDecision(forward=forward or None, replies=replies)
        if not isinstance(message, dict):
            return ClientDecision(forward=message)
        method = message.get("method")
        if not isinstance(method, str):
            return ClientDecision(forward=message)  # a response to a server request, e.g. sampling
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        if "id" in message:
            self.pending[message["id"]] = (method, params)

        target = _request_target(method, params)
        if target is None:
            return ClientDecision(forward=message)
        kind, item = target
        if item in self.removed.get(kind, set()):
            finding = RULES["MV706"].finding(
                self.server, item, None, f"{method} for an item removed by mcp-vet", kind=kind
            )
            self._report(finding, method, "blocked")
            self.pending.pop(message.get("id"), None)
            if "id" not in message:
                return ClientDecision(forward=None)
            return ClientDecision(forward=None, replies=[_refusal(message["id"], method, finding)])
        if kind in self.listed and item not in self.listed[kind] and not _matches_template(item, self.listed):
            finding = RULES["MV706"].finding(self.server, item, None, f"{method} for an item never listed", kind=kind)
            self._report(finding, method, "logged")
        return ClientDecision(forward=message)

    # --- Server to client ----------------------------------------------------------------

    def from_server(self, message: Any) -> Any | None:
        """Return a replacement message, or None to forward the original bytes unchanged."""
        if isinstance(message, list):
            replaced = [self.from_server(m) for m in message]
            if all(r is None for r in replaced):
                return None
            return [r if r is not None else m for r, m in zip(replaced, message, strict=True)]
        if not isinstance(message, dict) or "method" in message or "id" not in message:
            return None  # requests and notifications from the server pass through
        request = self.pending.pop(message["id"], None)
        result = message.get("result")
        if request is None or not isinstance(result, dict):
            return None
        method, params = request
        if method in LIST_METHODS:
            return self._inspect_list(message, method, result)
        if method in ("tools/call", "prompts/get", "resources/read"):
            return self._inspect_result(message, method, params, result)
        return None

    def _inspect_list(self, message: dict[str, Any], method: str, result: dict[str, Any]) -> dict[str, Any] | None:
        key, kind = LIST_METHODS[method]
        raw = result.get(key)
        if not isinstance(raw, list):
            return None
        items: list[tuple[str, str, dict[str, Any]]] = []  # (name, fingerprint, wire)
        snapshot = ServerSnapshot(name=self.server)
        for entry in raw:
            try:
                parsed = _parse_item(kind, entry)
            except ValueError:
                continue
            name = parsed.name if isinstance(parsed, ToolDef | PromptDef) else parsed.uri
            items.append((name, parsed.fingerprint(), entry))
            if isinstance(parsed, ToolDef):
                snapshot.tools.append(parsed)
            elif isinstance(parsed, PromptDef):
                snapshot.prompts.append(parsed)
            else:
                snapshot.resources.append(parsed)

        findings = scan([snapshot], pins=self._pins_for(kind), ignore=self.ignore)
        seen = self.seen.setdefault(kind, {})
        for name, digest, _ in items:
            if name in seen and seen[name] != digest:
                findings.append(
                    RULES["MV705"].finding(
                        self.server, name, None, f"was {seen[name][:12]}, now {digest[:12]}", kind=kind
                    )
                )
            seen[name] = digest

        blocked = {
            f.tool for f in findings if f.kind == kind and f.tool is not None and self._blocks(f)
        }  # f.tool is escaped with printable(); compare escaped names
        for f in findings:
            if f.rule_id in self.ignore:
                continue
            removed = self.mode is Mode.enforce and f.tool in blocked and f.kind == kind
            self._report(f, method, "removed" if removed else "logged")

        listed = self.listed.setdefault(kind, set())
        if self.mode is Mode.monitor or not blocked:
            listed.update(name for name, _, _ in items)
            return None
        kept = []
        for name, _, entry in items:
            if printable(name) in blocked:
                self.removed.setdefault(kind, set()).add(name)
            else:
                listed.add(name)
                kept.append(entry)
        return {**message, "result": {**result, key: kept}}

    def _inspect_result(
        self, message: dict[str, Any], method: str, params: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any] | None:
        target = _request_target(method, params) or ("tool", "?")
        kind, item = target
        findings = [f for f in inspect_result(self.server, kind, item, result) if f.rule_id not in self.ignore]
        block = self.mode is Mode.enforce and any(self._blocks(f) for f in findings)
        for f in findings:
            self._report(f, method, "blocked" if block and self._blocks(f) else "logged")
        if not block:
            return None
        worst = max((f for f in findings if self._blocks(f)), key=lambda f: f.severity)
        return _refusal(message["id"], method, worst)

    # --- Helpers ---------------------------------------------------------------------------

    def _blocks(self, finding: Finding) -> bool:
        return finding.severity >= self.block_on and finding.rule_id not in self.ignore

    def _pins_for(self, kind: str) -> Pins | None:
        if self.pins is None:
            return None
        server_pins = self.pins.get(self.server)
        if server_pins is None:
            return {}
        section = LOCK_SECTION[kind]
        return {self.server: {section: server_pins[section]}} if section in server_pins else {self.server: {}}

    def _report(self, finding: Finding, method: str, action: str) -> None:
        key = (finding.rule_id, finding.kind, finding.tool, finding.location, f"{action}:{finding.evidence}")
        if key in self._reported:
            return
        self._reported.add(key)
        event = Event(finding=finding, method=method, action=action)
        self.events.append(event)
        if self.on_event:
            self.on_event(event)


# --- Result inspection -----------------------------------------------------------------------


def inspect_result(server: str, kind: str, item: str, result: dict[str, Any]) -> list[Finding]:
    """Findings for one result. The same text often appears twice (as text content and as
    structuredContent), so each rule and evidence pair is reported once, at its first location."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for location, text in _result_texts(result):
        for f in inspect_text(server, kind, item, location, text):
            if (f.rule_id, f.evidence) not in seen:
                seen.add((f.rule_id, f.evidence))
                findings.append(f)
    return findings


def inspect_text(server: str, kind: str, item: str, location: str, text: str) -> list[Finding]:
    text = text[:MAX_SCAN_CHARS]
    out: list[Finding] = []

    hits = injection_matches(text)
    if hits:
        label, m = hits[0]
        labels = ", ".join(lbl for lbl, _ in hits)
        evidence = f"[{labels}] {_snippet(text, m.start(), m.end())}"
        out.append(RULES["MV701"].finding(server, item, location, evidence, kind=kind))

    hidden = _hidden_in_result(text)
    if hidden:
        severity, evidence = hidden
        out.append(RULES["MV702"].finding(server, item, location, evidence, severity=severity, kind=kind))

    for m in BASE64_RE.finditer(text):
        blob = m.group(0)
        if len(blob) > MAX_BASE64_CHARS:
            continue
        decoded = _try_base64(blob)
        if decoded and injection_matches(decoded):
            out.append(
                RULES["MV703"].finding(server, item, location, f"base64 decodes to: {decoded[:120]!r}", kind=kind)
            )
            break

    for label, pattern in SECRET_PATTERNS:
        m = pattern.search(text)
        if m:
            out.append(
                RULES["MV704"].finding(server, item, location, f"[{label}] {m.group(0)[:6]}... (redacted)", kind=kind)
            )
            break
    return out


def _hidden_in_result(text: str) -> tuple[Severity, str] | None:
    tags = overrides = other = 0
    for i, ch in enumerate(text):
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            tags += 1
        elif cp in _BIDI_OVERRIDES:
            overrides += 1
        elif cp in _BIDI or (cp in _ZERO_WIDTH and not (cp == 0xFEFF and i == 0)):
            other += 1
    if not (tags or overrides or other):
        return None
    parts = []
    if tags:
        parts.append(f"U+E0000 block (UNICODE TAG) x{tags}")
    if overrides:
        parts.append(f"bidi override x{overrides}")
    if other:
        parts.append(f"zero-width or bidi control x{other}")
    evidence = ", ".join(parts)
    decoded = _decode_tags(text)
    if decoded:
        evidence += f"; decoded tag text: {decoded[:120]!r}"
    return (Severity.HIGH if tags or overrides else Severity.MEDIUM), evidence


def _result_texts(result: dict[str, Any]) -> Iterable[tuple[str, str]]:
    """Every string a model may read from a tools/call, prompts/get or resources/read result."""
    for i, block in enumerate(result.get("content") or []):  # tools/call
        yield from _content_texts(f"content[{i}]", block)
    if "structuredContent" in result:
        yield from _strings("structuredContent", result["structuredContent"], 0)
    if isinstance(result.get("description"), str):  # prompts/get
        yield "description", result["description"]
    for i, msg in enumerate(result.get("messages") or []):
        if isinstance(msg, dict):
            content = msg.get("content")
            blocks = content if isinstance(content, list) else [content]
            for j, block in enumerate(blocks):
                yield from _content_texts(f"messages[{i}].content[{j}]", block)
    for i, contents in enumerate(result.get("contents") or []):  # resources/read
        if isinstance(contents, dict) and isinstance(contents.get("text"), str):
            yield f"contents[{i}].text", contents["text"]


def _content_texts(location: str, block: Any) -> Iterable[tuple[str, str]]:
    if not isinstance(block, dict):
        return
    if isinstance(block.get("text"), str):
        yield f"{location}.text", block["text"]
    resource = block.get("resource")
    if isinstance(resource, dict) and isinstance(resource.get("text"), str):
        yield f"{location}.resource.text", resource["text"]


def _strings(location: str, value: Any, depth: int) -> Iterable[tuple[str, str]]:
    if depth > 32:
        return
    if isinstance(value, str):
        yield location, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(f"{location}.{k}", v, depth + 1)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _strings(f"{location}[{i}]", v, depth + 1)


# --- Request helpers ---------------------------------------------------------------------------


def _request_target(method: str, params: dict[str, Any]) -> tuple[str, str] | None:
    if method in ("tools/call", "prompts/get"):
        name = params.get("name")
        return ("tool" if method == "tools/call" else "prompt", name) if isinstance(name, str) else None
    if method == "resources/read":
        uri = params.get("uri")
        return ("resource", uri) if isinstance(uri, str) else None
    return None


def _matches_template(uri: str, listed: dict[str, set[str]]) -> bool:
    """A resource read is expected if it matches any listed resource template."""
    for template in listed.get("template", set()):
        pattern = re.escape(template)
        pattern = re.sub(r"\\\{[^}]*\\\}", ".+", pattern)
        if re.fullmatch(pattern, uri):
            return True
    return False


def _parse_item(kind: str, entry: Any) -> ToolDef | PromptDef | ResourceDef:
    if kind == "tool":
        return ToolDef.from_wire(entry)
    if kind == "prompt":
        return PromptDef.from_wire(entry)
    return ResourceDef.from_wire(entry, template=kind == "template")


def _refusal(request_id: Any, method: str, finding: Finding) -> dict[str, Any]:
    # The message names the rule but never repeats the offending text back to the model.
    what = "request" if finding.rule_id == "MV706" else "result"
    text = f"mcp-vet blocked this {what}: {finding.rule_id} {finding.title}."
    if method == "tools/call":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": True},
        }
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32001, "message": text}}


def dumps(message: Any) -> bytes:
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
