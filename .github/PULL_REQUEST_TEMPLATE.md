## What this changes
Brief description of the change and why.

## Type
- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] Docs

## Safety checklist (offensive-security tool — required)
- [ ] No capability runs outside the scope validator / approval gate / kill switch.
- [ ] No new way to execute arbitrary commands outside the vetted adapter set.
- [ ] No secrets committed (`.env`, tokens, keys).
- [ ] Tests pass (`python -m pytest -q`) and the console typechecks (`cd console && npm run build`).

## Notes
Anything reviewers should know (trade-offs, follow-ups, manual test steps).
