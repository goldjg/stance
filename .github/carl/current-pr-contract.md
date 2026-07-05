# Current PR contract

## PR focus
Add initial GitHub Action packaging and documentation for STANCE.

## Included
- Add root `action.yml` composite action for STANCE local-build execution.
- Add example workflows under `docs/examples/github-actions/`:
  - `stance-microsoft365.yml`
  - `stance-facts-only.yml`
- Add `docs/github-action.md` with action contract and usage guidance.
- Update `README.md` with GitHub Action section and docs link.
- Update `docs/maester-parity.md` CI/CD and integration parity status notes.
- Update `.github/carl/memory.md` with durable action/auth/SARIF truths.
- Update current PR contract for focused scope and exclusions.

## Excluded
- New Microsoft API collectors.
- New posture checks.
- New providers.
- Released binary install mode in the action.
- GitHub OIDC-to-Entra token exchange implementation.
- `fail-on-findings` behavior wiring if not already present.
- Release pipeline implementation changes (except documentation references).

## Guardrails
- Keep STANCE runtime 100% Go.
- No PowerShell runtime/module dependency in STANCE CLI runtime.
- No shell-out from STANCE CLI runtime to `pwsh`, `az`, `mggraph`, Graph CLI, or Microsoft admin modules.
- Preserve provider-neutral core architecture and canonical `microsoft365` provider usage.
- Keep dependency footprint minimal and justified.
- Keep clean-room Maester boundaries.

## Validation requirements
- `gofmt -l .` clean.
- `go test ./...`.
- `go vet ./...`.
- Manual review of `action.yml` and example workflow correctness.
