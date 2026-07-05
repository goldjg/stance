# Current PR contract

## PR focus
Expand the Microsoft 365 Entra directory role collector foundation.

## Included
- Add Microsoft 365 role definition/assignment fact models under `internal/provider/microsoft365/facts`.
- Add direct Graph collection for Entra directory role definitions and assignments.
- Derive privileged principal facts from role assignments.
- Integrate role facts into the Microsoft 365 fact bundle and default collection flow.
- Add cautious role visibility checks:
  - `ENTRA-ROLE-001`
  - `ENTRA-ROLE-002`
- Update check catalog/suite listing and permissions output for role collection scope.
- Update docs and governance artifacts:
  - `README.md`
  - `docs/maester-parity.md`
  - `.github/carl/memory.md`
  - `.github/carl/current-pr-contract.md`
- Add/update tests for collector mapping, derivation, evaluator behavior, catalog/permissions, CLI output, and report compatibility.

## Excluded
- Emergency-access/break-glass pass/fail logic.
- Full Conditional Access coverage analysis for privileged principals.
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
