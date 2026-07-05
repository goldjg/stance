# Current PR contract

## PR focus
PR1 foundation bootstrap only.

## Included
- Go module initialization.
- CLI skeleton (`version`, `init`, help and planned command stubs).
- cARL governance bootstrap in `.github/carl/`.
- README project thesis, hard constraints, non-goals.
- GitHub Actions CI with gofmt/test/vet.

## Excluded
- Live Microsoft API calls.
- Auth provider implementation.
- Collectors, evaluators, and reporting logic.
- Remediation/write actions.

## Guardrails
- Keep changes minimal and reviewable.
- Preserve clean-room constraints.
- Keep dependencies minimal.
