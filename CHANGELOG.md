# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
