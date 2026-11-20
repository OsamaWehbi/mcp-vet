"""Metadata for every rule. Detection logic lives in the sibling modules."""

from __future__ import annotations

from dataclasses import dataclass

from mcp_vet.models import Finding, Severity, printable

LLM01 = "LLM01:2025 Prompt Injection"
LLM02 = "LLM02:2025 Sensitive Information Disclosure"
LLM03 = "LLM03:2025 Supply Chain"
LLM06 = "LLM06:2025 Excessive Agency"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    owasp: str
    description: str
    remediation: str

    def finding(
        self,
        server: str,
        tool: str | None = None,
        location: str | None = None,
        evidence: str = "",
        severity: Severity | None = None,
        kind: str = "tool",
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=severity if severity is not None else self.severity,
            server=printable(server) or "",
            tool=printable(tool),
            kind=kind,
            location=printable(location),
            evidence=printable(evidence) or "",
            owasp=self.owasp,
            remediation=self.remediation,
        )


_RULES = [
    # --- Poisoning (tools, prompts and resources) -----------------------------------
    Rule(
        "MV101",
        "Instructions aimed at the model in metadata",
        Severity.HIGH,
        LLM01,
        "Tool, parameter, prompt or resource text contains phrasing that tries to steer the model, such as telling it to "
        "ignore earlier instructions, hide actions from the user, or follow hidden <IMPORTANT> blocks.",
        "Descriptions should explain what a tool does, not instruct the model. Remove the text or do not install the server.",
    ),
    Rule(
        "MV102",
        "Reference to secrets or sensitive files",
        Severity.MEDIUM,
        LLM02,
        "Tool, prompt or resource text mentions credential stores or sensitive files such as SSH keys, .env files, cloud credentials "
        "or MCP client configs. Severity is raised when the text also asks for that data to be read or sent.",
        "A tool should never need the model to fetch secrets on its behalf. Review why the reference is there.",
    ),
    Rule(
        "MV103",
        "Hidden or invisible Unicode characters",
        Severity.HIGH,
        LLM01,
        "Zero-width, bidirectional-control or Unicode tag characters can hide instructions that a human reviewer "
        "cannot see but a model still reads.",
        "Strip the characters and review the decoded text. Legitimate metadata does not need them.",
    ),
    Rule(
        "MV104",
        "Encoded payload in metadata",
        Severity.MEDIUM,
        LLM01,
        "Long base64 or hex strings in descriptions can smuggle instructions past review. Severity is raised when "
        "the decoded text contains injection phrasing.",
        "Remove encoded blobs from descriptions or explain them in plain text.",
    ),
    Rule(
        "MV105",
        "Oversized or padded description",
        Severity.LOW,
        LLM01,
        "Very long descriptions, or long runs of blank lines and spaces, are a common way to push hidden "
        "instructions out of view in client UIs.",
        "Keep descriptions short and review the full text, not only what the UI shows.",
    ),
    # --- Over-permission -------------------------------------------------------------
    Rule(
        "MV201",
        "Arbitrary command or code execution",
        Severity.HIGH,
        LLM06,
        "The tool appears to run shell commands or evaluate code. Combined with any prompt injection, this gives "
        "an attacker code execution on the host.",
        "Replace with narrow, purpose-built tools, run the server in a sandbox, and require human approval per call.",
    ),
    Rule(
        "MV202",
        "Destructive or write access to the filesystem",
        Severity.MEDIUM,
        LLM06,
        "The tool can write, move or delete files, or declares destructiveHint.",
        "Restrict the server to an allowlisted directory and require confirmation for destructive calls.",
    ),
    Rule(
        "MV203",
        "Data exfiltration path within one server",
        Severity.HIGH,
        LLM06,
        "The same server exposes tools that read local data or secrets and tools that send data to the network. "
        "A single injected instruction can chain them to leak data.",
        "Split read and send capabilities across trust boundaries, or gate outbound tools behind approval.",
    ),
    Rule(
        "MV204",
        "Data exfiltration path across servers",
        Severity.MEDIUM,
        LLM06,
        "Across the scanned servers, an agent can both read local data or secrets and send data to the network.",
        "Avoid loading untrusted-content tools, local-data tools and outbound tools into the same agent session.",
    ),
    Rule(
        "MV205",
        "Annotations understate the tool's capability",
        Severity.MEDIUM,
        LLM06,
        "The tool declares readOnlyHint or destructiveHint=false, but its name or parameters suggest it writes, "
        "deletes, executes or sends data. Clients may skip confirmation based on these hints.",
        "Correct the annotations. Clients should treat annotations from untrusted servers as unverified.",
    ),
    Rule(
        "MV206",
        "Broadly privileged server",
        Severity.LOW,
        LLM06,
        "One server combines four or more capability classes (execute, write, read, network, secrets).",
        "Prefer several narrow servers so each agent only gets what it needs.",
    ),
    # --- Schema weaknesses -------------------------------------------------------------
    Rule(
        "MV301",
        "Unconstrained file path parameter",
        Severity.MEDIUM,
        LLM06,
        "A path-like string parameter has no pattern, enum or other constraint, so any path, including "
        "traversal sequences, can be passed.",
        "Validate paths server-side against an allowlisted root and document the constraint in the schema.",
    ),
    Rule(
        "MV302",
        "Free-text command, code or SQL parameter",
        Severity.MEDIUM,
        LLM06,
        "A parameter that looks like a command, script, code or SQL accepts any string.",
        "Expose structured parameters instead of raw commands, or constrain them with an enum.",
    ),
    Rule(
        "MV303",
        "URL parameter without an allowlist",
        Severity.LOW,
        LLM06,
        "A URL parameter accepts any value, which can enable SSRF or data exfiltration to attacker hosts.",
        "Restrict destinations server-side and describe the allowlist in the schema.",
    ),
    Rule(
        "MV304",
        "Missing or non-object input schema",
        Severity.LOW,
        LLM06,
        "The tool has no inputSchema or one that is not of type object, so clients cannot validate arguments.",
        "Declare an object schema with typed, documented properties.",
    ),
    # --- Rug pulls -------------------------------------------------------------
    Rule(
        "MV401",
        "Definition changed since it was pinned",
        Severity.HIGH,
        LLM03,
        "A tool, prompt or resource differs from the lockfile (for a tool: its description, schema or "
        "annotations). Servers can change behaviour after approval (a rug pull).",
        "Review the diff. If the change is expected, run with --update-lock to re-pin.",
    ),
    Rule(
        "MV402",
        "New definition not in the lockfile",
        Severity.MEDIUM,
        LLM03,
        "The server now exposes a tool, prompt or resource that was not present when the lockfile was written.",
        "Review it, then run with --update-lock to pin it.",
    ),
    Rule(
        "MV403",
        "Pinned definition was removed",
        Severity.LOW,
        LLM03,
        "A tool, prompt or resource recorded in the lockfile is no longer exposed by the server.",
        "Confirm the removal is expected, then run with --update-lock.",
    ),
    Rule(
        "MV404",
        "Server not in the lockfile",
        Severity.LOW,
        LLM03,
        "The server has no entry in the lockfile, so changes to its definitions cannot be detected.",
        "Run with --update-lock to pin it.",
    ),
    # --- Shadowing -------------------------------------------------------------
    Rule(
        "MV501",
        "Duplicate tool name across servers",
        Severity.MEDIUM,
        LLM03,
        "Two servers expose a tool with the same name. Depending on the client, one may silently shadow the other.",
        "Rename one of the tools or avoid loading both servers together.",
    ),
    Rule(
        "MV502",
        "Tool text references another server's tool",
        Severity.HIGH,
        LLM01,
        "A tool's metadata names a tool from a different server. This is the pattern used by cross-server "
        "shadowing attacks that change how a trusted tool is used.",
        "Tools should only describe themselves. Treat the referencing server as untrusted.",
    ),
    Rule(
        "MV503",
        "Confusable tool name",
        Severity.MEDIUM,
        LLM03,
        "The tool name contains non-ASCII characters or differs from another server's tool only by case or "
        "separators, which can be used to impersonate it.",
        "Use plain ASCII names that are clearly distinct.",
    ),
    # --- Prompts and resources -------------------------------------------------
    Rule(
        "MV601",
        "Resource exposes a sensitive local file",
        Severity.HIGH,
        LLM02,
        "A resource or resource template URI points at credentials, keys, environment files or system "
        "password files. Any client that reads the resource hands that data to the model.",
        "Do not expose secrets as resources. Remove the resource or point it at non-sensitive data.",
    ),
    Rule(
        "MV602",
        "Resource template allows arbitrary file paths",
        Severity.MEDIUM,
        LLM06,
        "A file:// resource template starts its path with a variable, or uses reserved ({+var}), fragment "
        "({#var}) or path ({/var}) expansion, so a model can request files outside the intended directory.",
        "Restrict the template to a fixed directory and validate the expanded path on the server.",
    ),
    Rule(
        "MV603",
        "Duplicate prompt name across servers",
        Severity.MEDIUM,
        LLM03,
        "Two servers expose a prompt with the same name. Clients often surface prompts as slash commands, "
        "so one server can impersonate another's prompt.",
        "Rename one of the prompts or avoid loading both servers together.",
    ),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULES}
