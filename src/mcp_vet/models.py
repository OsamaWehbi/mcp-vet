"""Core data models shared by loaders, rules and reporters."""

from __future__ import annotations

import hashlib
import json
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(IntEnum):
    """Finding severity. Ordered so that comparisons work (HIGH > MEDIUM)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {choices}") from exc

    def __str__(self) -> str:
        return self.name.lower()


class ToolDef(BaseModel):
    """A tool as advertised by an MCP server, in MCP wire format."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_wire(cls, data: dict[str, Any]) -> ToolDef:
        """Build from a `tools/list` entry (camelCase keys, as in the MCP spec)."""
        if not isinstance(data, dict) or not isinstance(data.get("name"), str):
            raise ValueError("each tool must be an object with a string 'name'")
        schema = data.get("inputSchema", data.get("input_schema")) or {}
        annotations = data.get("annotations") or {}
        return cls(
            name=data["name"],
            description=data.get("description") or "",
            input_schema=schema if isinstance(schema, dict) else {},
            annotations=annotations if isinstance(annotations, dict) else {},
        )

    def fingerprint(self) -> str:
        """Stable SHA-256 of everything the model sees about this tool."""
        payload = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": self.annotations,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def text_fields(self) -> list[tuple[str, str]]:
        """Every piece of free text a model will read, with a location label."""
        fields: list[tuple[str, str]] = []
        if self.description:
            fields.append(("description", self.description))
        title = self.annotations.get("title")
        if isinstance(title, str) and title:
            fields.append(("annotations.title", title))
        for path, node in iter_schema_nodes(self.input_schema):
            for key in ("description", "title"):
                value = node.get(key)
                if isinstance(value, str) and value:
                    fields.append((f"inputSchema{path}.{key}", value))
            default = node.get("default")
            if isinstance(default, str) and default:
                fields.append((f"inputSchema{path}.default", default))
            for i, item in enumerate(node.get("enum") or []):
                if isinstance(item, str) and item:
                    fields.append((f"inputSchema{path}.enum[{i}]", item))
        return fields


class ServerSnapshot(BaseModel):
    """The tools exposed by one MCP server at scan time."""

    name: str
    source: str = ""
    tools: list[ToolDef] = Field(default_factory=list)


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    server: str
    tool: str | None = None
    location: str | None = None
    evidence: str = ""
    owasp: str = ""
    remediation: str = ""

    def sort_key(self) -> tuple[int, str, str, str]:
        return (-int(self.severity), self.server, self.tool or "", self.rule_id)


def printable(text: str | None) -> str | None:
    """Escape control and invisible characters so hostile metadata cannot drive the terminal or hide in reports."""
    if text is None:
        return None
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in text)


def iter_schema_nodes(schema: Any, path: str = "") -> list[tuple[str, dict[str, Any]]]:
    """Walk a JSON Schema and yield (path, node) for every object node.

    Paths look like `.properties.path` so they can be shown in findings.
    Recursion is bounded to keep hostile schemas from exhausting the stack.
    """
    out: list[tuple[str, dict[str, Any]]] = []

    def walk(node: Any, p: str, depth: int) -> None:
        if not isinstance(node, dict) or depth > 32:
            return
        out.append((p, node))
        for key in ("properties", "patternProperties", "$defs", "definitions"):
            children = node.get(key)
            if isinstance(children, dict):
                for name, child in children.items():
                    walk(child, f"{p}.{key}.{name}", depth + 1)
        for key in ("items", "additionalProperties", "not"):
            if isinstance(node.get(key), dict):
                walk(node[key], f"{p}.{key}", depth + 1)
        for key in ("anyOf", "oneOf", "allOf"):
            if isinstance(node.get(key), list):
                for i, child in enumerate(node[key]):
                    walk(child, f"{p}.{key}[{i}]", depth + 1)

    walk(schema, path, 0)
    return out


def top_level_params(tool: ToolDef) -> dict[str, dict[str, Any]]:
    props = tool.input_schema.get("properties")
    if not isinstance(props, dict):
        return {}
    return {k: v for k, v in props.items() if isinstance(v, dict)}
