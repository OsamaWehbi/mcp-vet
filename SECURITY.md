# Security Policy

mcp-vet is a security tool, so its own behaviour matters. This document explains how to report a
vulnerability, what mcp-vet does and does not do when it scans, and its known limitations.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/OsamaWehbi/mcp-vet/security/advisories/new)
on this repository. You can expect an acknowledgement within 72 hours.

Useful reports include: a way to make mcp-vet execute or call something it should not, a crash or
hang caused by a crafted tool definition, or a reliable way to evade a rule that is not already
listed under known limitations below.

## What mcp-vet does when it scans

| Input | What happens |
|---|---|
| Offline JSON file | The file is parsed. Nothing is executed and no network connection is made. |
| `--http URL` | mcp-vet connects and sends `initialize` and the list methods only (`tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`). |
| `--stdio CMD` or `--config` with a `command` | mcp-vet **starts the server process**, then sends `initialize` and the list methods only. |

mcp-vet **never calls a scanned server's tools, gets its prompts or reads its resources**. However, starting a stdio server runs that server's
code with your user's permissions, exactly as an MCP client would. Only scan servers you would be
prepared to run, or scan them inside a container or a throwaway VM. For servers you do not trust at
all, ask for their `tools/list` output and scan it offline.

## What `mcp-vet proxy` does

The proxy starts the server command it is given, exactly as your MCP client would, and relays
JSON-RPC between the client and the server over stdio. It never sends a request of its own. In
monitor mode it forwards every message unchanged. In enforce mode it can remove items from list
responses, replace a result with an error, or answer a request for a removed item itself instead of
forwarding it.

The proxy sees all traffic, including tool arguments and results. It writes only findings to stderr
and to `--log`: rule, target, location and a short evidence snippet. Secrets matched by MV704 are
redacted to a six-character prefix. Evidence snippets from other rules quote the offending text, so
treat the log as sensitive if your tools handle private data.

## Threat model (summary)

| Threat | Control |
|---|---|
| Hostile tool metadata crashes or hangs the scanner | Input files are capped at 20 MB, schema walking is depth-limited, regexes avoid nested quantifiers, live connections time out |
| Hidden characters hide evidence from the reviewer | Evidence escapes non-printable characters; snapshots are written ASCII-escaped; Unicode tag text is decoded and shown |
| Terminal escape sequences in tool text | Rich markup is escaped and control characters are shown as `\uXXXX` |
| Report injection into Markdown summaries | Table separators and backticks are escaped |
| Shell injection through the GitHub Action inputs | Inputs are passed as environment variables and split into an argument array, never interpolated into the script |
| Secrets in client configs | `${VAR}` references in `env` and `headers` are expanded at run time; values are never printed or written to reports or snapshots |
| Injected text in results reaching the model through the proxy's own messages | Block messages name the rule only and never repeat the offending text |
| Bypassing enforce mode with a JSON-RPC batch | Batches are checked request by request |
| Hostile servers flooding the proxy | Messages over 64 MB end the session; each string is scanned up to 1 MB |

## Known limitations

- Detection is heuristic. A determined attacker can phrase instructions that no pattern matches, so a
  clean report is not proof that a server is safe. Treat mcp-vet as one layer, alongside sandboxing,
  least privilege and human approval of sensitive tool calls.
- `mcp-vet scan` only sees what a server advertises at scan time. A server can behave differently at
  run time or return malicious content in tool results. Use `--lock` in CI to catch definition
  changes, and `mcp-vet proxy` to check results while an agent runs.
- The proxy supports stdio servers only, and checks text content only (not images, audio or binary
  resource blobs). Results are scanned up to 1 MB per string.
- Capability classification uses tool and parameter names. A tool named innocently that does
  something dangerous will not be flagged by the MV2xx rules.

## Supported versions

Only the latest release receives security fixes during the 0.x series.
