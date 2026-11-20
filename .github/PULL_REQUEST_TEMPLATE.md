## Summary

What does this change and why?

## Type of change

- [ ] Bug fix
- [ ] New rule or detection improvement
- [ ] New input format or output format
- [ ] Documentation
- [ ] Refactor or chore

## Checklist

- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `pytest` passes and new behaviour has tests
- [ ] New or changed rules have a positive test and a false-positive test
- [ ] `docs/rules.md` regenerated with `python scripts/gen_rules_doc.py` if rules changed
- [ ] No secrets, private tool definitions or real customer data included
- [ ] mcp-vet still never calls a scanned server's tools
