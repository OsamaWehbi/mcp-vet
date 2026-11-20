# Contributing to mcp-vet

Thanks for your interest in improving mcp-vet. Contributions of all sizes are welcome, including bug
reports, false-positive reports, new rules, new input formats and documentation fixes.

## Getting set up

```bash
git clone https://github.com/OsamaWehbi/mcp-vet.git
cd mcp-vet
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

## Before you open a pull request

```bash
ruff check .
ruff format --check .
pytest
```

CI runs the same checks on Python 3.11, 3.12 and 3.13 on Linux and on Windows, plus Bandit,
pip-audit, Gitleaks and a self-test of the GitHub Action.

## Adding or changing a rule

1. Add the rule's metadata to `src/mcp_vet/rules/registry.py`. Pick the next free ID in the right
   family (MV1 poisoning, MV2 permissions, MV3 schema, MV4 lockfile, MV5 shadowing).
2. Implement detection in the matching module under `src/mcp_vet/rules/`.
3. Add tests with at least one tool definition that must trigger the rule and one realistic, benign
   definition that must not. False positives erode trust faster than misses.
4. Regenerate the reference: `python scripts/gen_rules_doc.py`.
5. If a demo server should now trigger the rule, update it under `examples/servers/` and regenerate
   the snapshot:

   ```bash
   mcp-vet scan -c examples/mcp.json --save-snapshot examples/demo-snapshot.json --fail-on none
   ```

## Guidelines

- Open an issue first for larger changes so we can agree on the approach.
- Keep pull requests focused. One topic per PR is easier to review.
- Use conventional commit messages such as `feat`, `fix`, `docs`, `test` and `chore`.
- mcp-vet must never call a scanned server's tools. Only `initialize` and `tools/list` are allowed.
- Keep detection deterministic and explainable. Every finding should say what matched and where.
- Never commit secrets or real, private tool definitions. Demo servers must stay harmless.

## Reporting security issues

Please do not open a public issue for a vulnerability. Follow the process in [SECURITY.md](SECURITY.md).
