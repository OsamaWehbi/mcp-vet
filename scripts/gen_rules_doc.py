"""Regenerate docs/rules.md from the rule registry: python scripts/gen_rules_doc.py"""

from pathlib import Path

from mcp_vet.rules import RULES

SECTIONS = {
    "MV1": "Tool poisoning",
    "MV2": "Over-permission",
    "MV3": "Schema weaknesses",
    "MV4": "Rug pulls (needs --lock)",
    "MV5": "Shadowing",
    "MV6": "Prompts and resources",
    "MV7": "Runtime (mcp-vet proxy only)",
}

lines = [
    "# Rules",
    "",
    "Generated from `src/mcp_vet/rules/registry.py` by `scripts/gen_rules_doc.py`. Do not edit by hand.",
    "",
    "Severities are defaults. Some rules raise severity when the evidence is stronger, as noted in the description.",
    "Skip a rule with `--ignore MV105` and hide low-severity results with `--min-severity medium`.",
    "",
    "| Rule | Severity | Title | OWASP |",
    "| --- | --- | --- | --- |",
]
lines += [f"| [{r.id}](#{r.id.lower()}) | {r.severity} | {r.title} | {r.owasp} |" for r in RULES.values()]
current = None
for r in RULES.values():
    section = SECTIONS[r.id[:3]]
    if section != current:
        lines += ["", f"## {section}"]
        current = section
    lines += [
        "",
        f"### {r.id}",
        "",
        f"**{r.title}** - default severity `{r.severity}` - {r.owasp}",
        "",
        r.description,
        "",
        f"**Remediation:** {r.remediation}",
    ]
Path(__file__).resolve().parent.parent.joinpath("docs", "rules.md").write_text(
    "\n".join(lines) + "\n", encoding="utf-8"
)
