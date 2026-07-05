# Current PR contract

## PR focus
Improve GitHub Action live-collection auth ergonomics with action-native GitHub OIDC assertion acquisition.

## Included
- Update root `action.yml` auth inputs and mode handling (`env`, `github-oidc`).
- Add action-native GitHub OIDC assertion acquisition for live collection and export to `STANCE_CLIENT_ASSERTION`.
- Preserve facts-only behavior and existing env-driven auth behavior.
- Update docs/examples:
  - `docs/examples/github-actions/stance-microsoft365.yml`
  - `docs/github-action.md`
- Update `README.md` GitHub Action section and docs link.
- Update `docs/maester-parity.md` parity status wording for GitHub Action/OIDC progress.
- Update `.github/carl/memory.md` with durable OIDC/auth truths.
- Update this PR contract for focused scope and exclusions.

## Excluded
- Entra app/service principal provisioning and federated credential creation.
- New Microsoft API collectors.
- New posture checks.
- New providers.
- Released binary install mode in the action.
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
