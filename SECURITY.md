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
| `--http URL` | mcp-vet connects and sends `initialize` and `tools/list` only. |
| `--stdio CMD` or `--config` with a `command` | mcp-vet **starts the server process**, then sends `initialize` and `tools/list` only. |

mcp-vet **never calls a scanned server's tools**. However, starting a stdio server runs that server's
code with your user's permissions, exactly as an MCP client would. Only scan servers you would be
prepared to run, or scan them inside a container or a throwaway VM. For servers you do not trust at
all, ask for their `tools/list` output and scan it offline.

## Threat model (summary)

| Threat | Control |
|---|---|
| Hostile tool metadata crashes or hangs the scanner | Input files are capped at 20 MB, schema walking is depth-limited, regexes avoid nested quantifiers, live connections time out |
| Hidden characters hide evidence from the reviewer | Evidence escapes non-printable characters; snapshots are written ASCII-escaped; Unicode tag text is decoded and shown |
| Terminal escape sequences in tool text | Rich markup is escaped and control characters are shown as `\uXXXX` |
| Report injection into Markdown summaries | Table separators and backticks are escaped |
| Shell injection through the GitHub Action inputs | Inputs are passed as environment variables and split into an argument array, never interpolated into the script |
| Secrets in client configs | `${VAR}` references in `env` and `headers` are expanded at run time; values are never printed or written to reports or snapshots |

## Known limitations

- Detection is heuristic. A determined attacker can phrase instructions that no pattern matches, so a
  clean report is not proof that a server is safe. Treat mcp-vet as one layer, alongside sandboxing,
  least privilege and human approval of sensitive tool calls.
- mcp-vet only sees what a server advertises at scan time. A server can behave differently at run
  time or return malicious content in tool results. Use `--lock` in CI to catch definition changes.
- Capability classification uses tool and parameter names. A tool named innocently that does
  something dangerous will not be flagged by the MV2xx rules.

## Supported versions

Only the latest release receives security fixes during the 0.x series.
