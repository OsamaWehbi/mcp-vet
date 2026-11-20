# Rules

Generated from `src/mcp_vet/rules/registry.py` by `scripts/gen_rules_doc.py`. Do not edit by hand.

Severities are defaults. Some rules raise severity when the evidence is stronger, as noted in the description.
Skip a rule with `--ignore MV105` and hide low-severity results with `--min-severity medium`.

| Rule | Severity | Title | OWASP |
| --- | --- | --- | --- |
| [MV101](#mv101) | high | Instructions aimed at the model in tool metadata | LLM01:2025 Prompt Injection |
| [MV102](#mv102) | medium | Reference to secrets or sensitive files | LLM02:2025 Sensitive Information Disclosure |
| [MV103](#mv103) | high | Hidden or invisible Unicode characters | LLM01:2025 Prompt Injection |
| [MV104](#mv104) | medium | Encoded payload in tool metadata | LLM01:2025 Prompt Injection |
| [MV105](#mv105) | low | Oversized or padded description | LLM01:2025 Prompt Injection |
| [MV201](#mv201) | high | Arbitrary command or code execution | LLM06:2025 Excessive Agency |
| [MV202](#mv202) | medium | Destructive or write access to the filesystem | LLM06:2025 Excessive Agency |
| [MV203](#mv203) | high | Data exfiltration path within one server | LLM06:2025 Excessive Agency |
| [MV204](#mv204) | medium | Data exfiltration path across servers | LLM06:2025 Excessive Agency |
| [MV205](#mv205) | medium | Annotations understate the tool's capability | LLM06:2025 Excessive Agency |
| [MV206](#mv206) | low | Broadly privileged server | LLM06:2025 Excessive Agency |
| [MV301](#mv301) | medium | Unconstrained file path parameter | LLM06:2025 Excessive Agency |
| [MV302](#mv302) | medium | Free-text command, code or SQL parameter | LLM06:2025 Excessive Agency |
| [MV303](#mv303) | low | URL parameter without an allowlist | LLM06:2025 Excessive Agency |
| [MV304](#mv304) | low | Missing or non-object input schema | LLM06:2025 Excessive Agency |
| [MV401](#mv401) | high | Tool definition changed since it was pinned | LLM03:2025 Supply Chain |
| [MV402](#mv402) | medium | New tool not in the lockfile | LLM03:2025 Supply Chain |
| [MV403](#mv403) | low | Pinned tool was removed | LLM03:2025 Supply Chain |
| [MV404](#mv404) | low | Server not in the lockfile | LLM03:2025 Supply Chain |
| [MV501](#mv501) | medium | Duplicate tool name across servers | LLM03:2025 Supply Chain |
| [MV502](#mv502) | high | Tool text references another server's tool | LLM01:2025 Prompt Injection |
| [MV503](#mv503) | medium | Confusable tool name | LLM03:2025 Supply Chain |

## Tool poisoning

### MV101

**Instructions aimed at the model in tool metadata** - default severity `high` - LLM01:2025 Prompt Injection

Tool or parameter text contains phrasing that tries to steer the model, such as telling it to ignore earlier instructions, hide actions from the user, or follow hidden <IMPORTANT> blocks.

**Remediation:** Descriptions should explain what a tool does, not instruct the model. Remove the text or do not install the server.

### MV102

**Reference to secrets or sensitive files** - default severity `medium` - LLM02:2025 Sensitive Information Disclosure

Tool text mentions credential stores or sensitive files such as SSH keys, .env files, cloud credentials or MCP client configs. Severity is raised when the text also asks for that data to be read or sent.

**Remediation:** A tool should never need the model to fetch secrets on its behalf. Review why the reference is there.

### MV103

**Hidden or invisible Unicode characters** - default severity `high` - LLM01:2025 Prompt Injection

Zero-width, bidirectional-control or Unicode tag characters can hide instructions that a human reviewer cannot see but a model still reads.

**Remediation:** Strip the characters and review the decoded text. Legitimate tool metadata does not need them.

### MV104

**Encoded payload in tool metadata** - default severity `medium` - LLM01:2025 Prompt Injection

Long base64 or hex strings in descriptions can smuggle instructions past review. Severity is raised when the decoded text contains injection phrasing.

**Remediation:** Remove encoded blobs from descriptions or explain them in plain text.

### MV105

**Oversized or padded description** - default severity `low` - LLM01:2025 Prompt Injection

Very long descriptions, or long runs of blank lines and spaces, are a common way to push hidden instructions out of view in client UIs.

**Remediation:** Keep descriptions short and review the full text, not only what the UI shows.

## Over-permission

### MV201

**Arbitrary command or code execution** - default severity `high` - LLM06:2025 Excessive Agency

The tool appears to run shell commands or evaluate code. Combined with any prompt injection, this gives an attacker code execution on the host.

**Remediation:** Replace with narrow, purpose-built tools, run the server in a sandbox, and require human approval per call.

### MV202

**Destructive or write access to the filesystem** - default severity `medium` - LLM06:2025 Excessive Agency

The tool can write, move or delete files, or declares destructiveHint.

**Remediation:** Restrict the server to an allowlisted directory and require confirmation for destructive calls.

### MV203

**Data exfiltration path within one server** - default severity `high` - LLM06:2025 Excessive Agency

The same server exposes tools that read local data or secrets and tools that send data to the network. A single injected instruction can chain them to leak data.

**Remediation:** Split read and send capabilities across trust boundaries, or gate outbound tools behind approval.

### MV204

**Data exfiltration path across servers** - default severity `medium` - LLM06:2025 Excessive Agency

Across the scanned servers, an agent can both read local data or secrets and send data to the network.

**Remediation:** Avoid loading untrusted-content tools, local-data tools and outbound tools into the same agent session.

### MV205

**Annotations understate the tool's capability** - default severity `medium` - LLM06:2025 Excessive Agency

The tool declares readOnlyHint or destructiveHint=false, but its name or parameters suggest it writes, deletes, executes or sends data. Clients may skip confirmation based on these hints.

**Remediation:** Correct the annotations. Clients should treat annotations from untrusted servers as unverified.

### MV206

**Broadly privileged server** - default severity `low` - LLM06:2025 Excessive Agency

One server combines four or more capability classes (execute, write, read, network, secrets).

**Remediation:** Prefer several narrow servers so each agent only gets what it needs.

## Schema weaknesses

### MV301

**Unconstrained file path parameter** - default severity `medium` - LLM06:2025 Excessive Agency

A path-like string parameter has no pattern, enum or other constraint, so any path, including traversal sequences, can be passed.

**Remediation:** Validate paths server-side against an allowlisted root and document the constraint in the schema.

### MV302

**Free-text command, code or SQL parameter** - default severity `medium` - LLM06:2025 Excessive Agency

A parameter that looks like a command, script, code or SQL accepts any string.

**Remediation:** Expose structured parameters instead of raw commands, or constrain them with an enum.

### MV303

**URL parameter without an allowlist** - default severity `low` - LLM06:2025 Excessive Agency

A URL parameter accepts any value, which can enable SSRF or data exfiltration to attacker hosts.

**Remediation:** Restrict destinations server-side and describe the allowlist in the schema.

### MV304

**Missing or non-object input schema** - default severity `low` - LLM06:2025 Excessive Agency

The tool has no inputSchema or one that is not of type object, so clients cannot validate arguments.

**Remediation:** Declare an object schema with typed, documented properties.

## Rug pulls (needs --lock)

### MV401

**Tool definition changed since it was pinned** - default severity `high` - LLM03:2025 Supply Chain

The tool's name, description, schema or annotations differ from the lockfile. Servers can change tool behaviour after approval (a rug pull).

**Remediation:** Review the diff. If the change is expected, run with --update-lock to re-pin.

### MV402

**New tool not in the lockfile** - default severity `medium` - LLM03:2025 Supply Chain

The server now exposes a tool that was not present when the lockfile was written.

**Remediation:** Review the new tool, then run with --update-lock to pin it.

### MV403

**Pinned tool was removed** - default severity `low` - LLM03:2025 Supply Chain

A tool recorded in the lockfile is no longer exposed by the server.

**Remediation:** Confirm the removal is expected, then run with --update-lock.

### MV404

**Server not in the lockfile** - default severity `low` - LLM03:2025 Supply Chain

The server has no entry in the lockfile, so changes to its tools cannot be detected.

**Remediation:** Run with --update-lock to pin it.

## Shadowing

### MV501

**Duplicate tool name across servers** - default severity `medium` - LLM03:2025 Supply Chain

Two servers expose a tool with the same name. Depending on the client, one may silently shadow the other.

**Remediation:** Rename one of the tools or avoid loading both servers together.

### MV502

**Tool text references another server's tool** - default severity `high` - LLM01:2025 Prompt Injection

A tool's metadata names a tool from a different server. This is the pattern used by cross-server shadowing attacks that change how a trusted tool is used.

**Remediation:** Tools should only describe themselves. Treat the referencing server as untrusted.

### MV503

**Confusable tool name** - default severity `medium` - LLM03:2025 Supply Chain

The tool name contains non-ASCII characters or differs from another server's tool only by case or separators, which can be used to impersonate it.

**Remediation:** Use plain ASCII names that are clearly distinct.
