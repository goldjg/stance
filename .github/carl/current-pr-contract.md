# Current PR contract

## PR focus
Add cautious privileged principal Conditional Access evidence evaluation.

## Included
- Add Microsoft 365 privileged CA evidence model/helper under `internal/provider/microsoft365/eval`.
- Derive cautious privileged-principal CA evidence from existing facts:
  - conditional access policies
  - directory role assignments
  - privileged principals
- Add cautious privileged CA evidence checks:
  - `ENTRA-CA-006`
  - `ENTRA-CA-007`
  - `ENTRA-CA-008`
- Update evaluator/catalog metadata and check discovery output.
- Update docs and governance artifacts:
  - `README.md`
  - `docs/maester-parity.md`
  - `.github/carl/memory.md`
  - `.github/carl/current-pr-contract.md`
- Add/update tests for evidence derivation, cautious check behavior, catalog/CLI discovery, and report/SARIF compatibility.

## Excluded
- New collectors or Graph endpoint additions.
- Graph group expansion (including nested/dynamic groups).
- Emergency-access/break-glass pass/fail logic.
- Full effective Conditional Access simulation or What-If parity.
- Non-Entra workload expansion (Exchange, SharePoint, Teams, Defender, Purview).
- Remediation/write actions.
- New providers.
- PowerShell/runtime/module integrations, shell-outs, or Microsoft SDK dependencies.

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
- Manual review that role checks remain cautious and do not overclaim emergency-access/CA outcomes.
