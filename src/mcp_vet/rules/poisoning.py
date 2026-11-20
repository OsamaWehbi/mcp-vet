"""Tool poisoning: hidden or model-directed instructions in tool metadata."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

from mcp_vet.models import Finding, ServerSnapshot, Severity
from mcp_vet.rules.registry import RULES

INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore earlier instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|other|system)\s+"
            r"(instructions?|prompts?|rules|directions|guidelines)",
            re.I,
        ),
    ),
    (
        "hide action from the user",
        re.compile(
            r"\b(do\s+not|don't|never)\s+(tell|inform|mention|reveal|notify|alert|show|disclose)\b[^.\n]{0,40}\buser\b",
            re.I,
        ),
    ),
    (
        "act without the user's knowledge",
        re.compile(r"\bwithout\s+(telling|informing|notifying|asking|alerting)\s+(the\s+)?user", re.I),
    ),
    (
        "hidden instruction block",
        re.compile(r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin)\s*>", re.I),
    ),
    ("chat template tokens", re.compile(r"\[/?INST\]|<\|im_(start|end)\|>|<\|(system|user|assistant)\|>", re.I)),
    (
        "precondition on other tool use",
        re.compile(
            r"\b(before|prior\s+to)\s+(using|calling|invoking|running)\s+(this|any|the|every)\b[^.\n]{0,40}\b(you\s+)?"
            r"(must|should|need\s+to|have\s+to|always)\b",
            re.I,
        ),
    ),
    (
        "covert behaviour",
        re.compile(
            r"\b(secretly|covertly)\b|\bsilently\s+(send|forward|copy|upload|include|exfiltrate|call|read)", re.I
        ),
    ),
    ("role reassignment", re.compile(r"\byou\s+are\s+now\s+(in\s+|a\s+|an\s+)|\bnew\s+system\s+prompt\b", re.I)),
    (
        "prompt extraction",
        re.compile(
            r"\b(reveal|print|output|repeat|leak|return)\s+(your\s+|the\s+)?(system\s+prompt|hidden\s+instructions)",
            re.I,
        ),
    ),
    (
        "behaviour override for other tools",
        re.compile(
            r"\b(when|whenever|if)\s+(the\s+)?(user|assistant|agent)\s+(calls?|uses?|invokes?)\b[^.\n]{0,60}\b(instead|also|always|must)\b",
            re.I,
        ),
    ),
]

SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("SSH keys", re.compile(r"~?/?\.ssh\b|\bid_(rsa|ed25519|ecdsa|dsa)\b|\bauthorized_keys\b", re.I)),
    ("environment files", re.compile(r"(?<![\w.])\.env(\.\w+)?\b", re.I)),
    (
        "cloud credentials",
        re.compile(r"\.aws/credentials|\.azure/|gcloud/(credentials|application_default)|\.kube/config", re.I),
    ),
    ("MCP or agent config", re.compile(r"\bmcp\.json\b|\w+_desktop_config\b|\.cursor/mcp|\bmcp_config\b", re.I)),
    ("system password files", re.compile(r"/etc/(passwd|shadow)\b", re.I)),
    ("private keys", re.compile(r"\bprivate[\s_-]?keys?\b|\.pem\b", re.I)),
    (
        "tokens or API keys",
        re.compile(r"\b(api[\s_-]?keys?|access[\s_-]?tokens?|bearer\s+tokens?|session\s+cookies?)\b", re.I),
    ),
    (
        "browser or wallet data",
        re.compile(r"\b(cookies\.sqlite|Login\s+Data|wallet\.dat|seed\s+phrase|mnemonic)\b", re.I),
    ),
]

EXFIL_VERBS = re.compile(
    r"\b(read|send|include|pass|attach|upload|forward|copy|cat|append|provide|post|transmit)\b", re.I
)

HIDDEN_CHARS = {
    **{cp: "ZERO WIDTH" for cp in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E)},
    **{cp: "BIDI CONTROL" for cp in (*range(0x202A, 0x202F), *range(0x2066, 0x206A), 0x200E, 0x200F, 0x061C)},
}

BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"\b[0-9a-fA-F]{64,}\b")
PADDING_RE = re.compile(r"\n{15,}|[ \t\u00a0]{120,}")
MAX_DESCRIPTION = 2000


def _snippet(text: str, start: int, end: int, width: int = 50) -> str:
    lo, hi = max(0, start - width), min(len(text), end + width)
    s = re.sub(r"\s+", " ", text[lo:hi]).strip()
    s = "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in s)
    return ("..." if lo else "") + s + ("..." if hi < len(text) else "")


def injection_matches(text: str) -> list[tuple[str, re.Match[str]]]:
    hits = []
    for label, pattern in INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            hits.append((label, m))
    return hits


def _hidden_chars(text: str) -> list[str]:
    found: dict[str, int] = {}
    for ch in text:
        cp = ord(ch)
        kind = HIDDEN_CHARS.get(cp)
        if kind is None and 0xE0000 <= cp <= 0xE007F:
            kind = "UNICODE TAG"
        if kind is None and unicodedata.category(ch) == "Cf" and cp not in (0x00AD,):
            kind = "FORMAT CONTROL"
        if kind:
            key = "U+E0000 block (UNICODE TAG)" if kind == "UNICODE TAG" else f"U+{cp:04X} ({kind})"
            found[key] = found.get(key, 0) + 1
    return [f"{k} x{v}" for k, v in found.items()]


def _decode_tags(text: str) -> str:
    """Unicode tag characters map 1:1 onto ASCII; decode them so reviewers can read the hidden text."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def _try_base64(blob: str) -> str | None:
    if not (re.search(r"[a-z]", blob) and re.search(r"[A-Z]", blob) and re.search(r"[0-9+/]", blob)):
        return None
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(c.isprintable() or c.isspace() for c in text)
    return text if text and printable / len(text) > 0.9 else None


def check(servers: list[ServerSnapshot]) -> list[Finding]:
    findings: list[Finding] = []
    for server in servers:
        for tool in server.tools:
            for location, text in tool.text_fields():
                findings.extend(_check_text(server.name, tool.name, location, text))
            if len(tool.description) > MAX_DESCRIPTION:
                findings.append(
                    RULES["MV105"].finding(
                        server.name, tool.name, "description", f"description is {len(tool.description)} characters long"
                    )
                )
    return findings


def _check_text(server: str, tool: str, location: str, text: str) -> list[Finding]:
    out: list[Finding] = []

    hits = injection_matches(text)
    if hits:
        label, m = hits[0]
        labels = ", ".join(lbl for lbl, _ in hits)
        out.append(RULES["MV101"].finding(server, tool, location, f"[{labels}] {_snippet(text, m.start(), m.end())}"))

    for label, pattern in SENSITIVE_PATTERNS:
        m = pattern.search(text)
        if m:
            window = text[max(0, m.start() - 80) : m.end() + 80]
            escalate = bool(EXFIL_VERBS.search(window)) and bool(
                hits or re.search(r"\b(must|always|first|before)\b", window, re.I)
            )
            out.append(
                RULES["MV102"].finding(
                    server,
                    tool,
                    location,
                    f"[{label}] {_snippet(text, m.start(), m.end())}",
                    severity=Severity.HIGH if escalate else None,
                )
            )
            break

    hidden = _hidden_chars(text)
    if hidden:
        evidence = ", ".join(hidden)
        decoded = _decode_tags(text)
        if decoded:
            evidence += f"; decoded tag text: {decoded[:120]!r}"
        out.append(RULES["MV103"].finding(server, tool, location, evidence))

    for m in BASE64_RE.finditer(text):
        decoded = _try_base64(m.group(0))
        if decoded is None:
            continue
        severity = Severity.HIGH if injection_matches(decoded) else None
        out.append(
            RULES["MV104"].finding(server, tool, location, f"base64 decodes to: {decoded[:120]!r}", severity=severity)
        )
        break
    else:
        m = HEX_RE.search(text)
        if m:
            out.append(RULES["MV104"].finding(server, tool, location, f"{len(m.group(0))}-character hex string"))

    m = PADDING_RE.search(text)
    if m:
        out.append(
            RULES["MV105"].finding(
                server, tool, location, f"{len(m.group(0))} consecutive whitespace characters at offset {m.start()}"
            )
        )
    return out
