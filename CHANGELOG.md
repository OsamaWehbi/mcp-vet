# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Prompts and resources are scanned, not only tools. Live scans also call `prompts/list`, `resources/list` and `resources/templates/list` when the server supports them, and offline inputs and snapshots can contain them.
- The poisoning rules (MV101 to MV105) and cross-server references (MV502) now cover prompt and resource text.
- New rules MV601 (resource exposes a sensitive local file), MV602 (`file://` template that reaches any path) and MV603 (duplicate prompt name across servers).
- Findings carry a `kind` (`tool`, `prompt`, `resource` or `template`); targets are shown as `server/prompt:name`.

- `mcp-vet proxy`, a stdio proxy that checks MCP traffic while an agent runs. Monitor mode logs findings; enforce mode removes flagged definitions from lists, replaces flagged results with an error and refuses calls to removed items. Findings go to stderr and, with `--log`, to a JSON Lines file.
- Runtime rules MV701 to MV706: injected instructions, hidden Unicode, encoded instructions and secrets in results, definitions that change during a session, and calls to unlisted or removed items.
- A runtime demo server whose definitions are clean but whose results are hostile.

### Changed
- Lockfile version 2 pins prompts, resources and templates as well as tools. Version 1 lockfiles are still read, and only their tools are checked.
- Rule titles MV101 and MV104 no longer say "tool metadata", since they apply to prompts and resources too.

## [0.1.0]

### Added
- `mcp-vet scan` for offline tool definitions (`tools/list` results, JSON-RPC responses and snapshots), MCP client configs, stdio servers and Streamable HTTP servers.
- Tool poisoning rules (MV101 to MV105): model-directed instructions, sensitive file references, hidden Unicode with tag-text decoding, encoded payloads and padded descriptions.
- Over-permission rules (MV201 to MV206): command execution, destructive filesystem access, exfiltration paths within and across servers, misleading annotations and broadly privileged servers.
- Schema rules (MV301 to MV304): unconstrained path, command and URL parameters, and missing schemas.
- Rug-pull detection with a lockfile of tool fingerprints (MV401 to MV404).
- Shadowing rules (MV501 to MV503): duplicate names, cross-server tool references and confusable names.
- Findings mapped to the OWASP Top 10 for LLM Applications 2025.
- Table, JSON, SARIF 2.1.0 and Markdown output, CI exit codes and a composite GitHub Action.
- Deliberately vulnerable demo servers and a test harness that checks each rule fires on them and not on a clean server.
