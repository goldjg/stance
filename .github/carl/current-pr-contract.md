# Current PR contract

## PR focus
Add released-binary install mode support to the STANCE GitHub Action.

## Included
- Update root `action.yml` install behavior for:
  - `stance-version: local` (unchanged local build behavior)
  - `stance-version: latest` (latest release resolution + install)
  - `stance-version: vX.Y.Z` (pinned release install)
- Enforce checksum verification for released-binary mode:
  - download selected archive + `checksums.txt`
  - require archive entry in checksums
  - fail on missing or mismatched SHA-256
- Preserve action auth and runtime behavior:
  - facts-only remains auth-free
  - `auth-mode: env` remains supported
  - `auth-mode: github-oidc` remains supported
  - collect/check/report flow remains unchanged after binary install
- Update docs/examples:
  - `docs/github-action.md`
  - `docs/examples/github-actions/stance-microsoft365.yml`
  - `docs/examples/github-actions/stance-facts-only.yml`
- Update `README.md` GitHub Action section and docs link/guidance.
- Update `docs/maester-parity.md` CI/CD and action-integration progress wording.
- Update `.github/carl/memory.md` with durable install/auth truths.
- Keep this contract aligned with final scope.

## Excluded
- New Microsoft API collectors.
- New posture checks.
- New providers.
- Entra app/service principal provisioning and federated credential creation.
- `fail-on-findings` behavior implementation.
- Release workflow/pipeline implementation changes (except strictly necessary naming docs alignment).

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
- Manual review of `action.yml` install/auth behavior and docs/example correctness.
