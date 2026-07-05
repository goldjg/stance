# Current PR contract

## PR focus
Add structured evidence details to durable result JSON for cautious privileged principal Conditional Access evidence findings.

## Included
- Add optional provider-neutral structured finding details field in core result plumbing.
- Populate privileged CA machine-readable evidence payload in finding details for:
  - `ENTRA-CA-006`
  - `ENTRA-CA-007`
  - `ENTRA-CA-008`
- Keep `stance check --format json` and `stance report --results ... --format json` preserving finding details.
- Add/adjust tests for details serialization/round-trip and report compatibility.
- Update docs and governance artifacts:
  - `README.md`
  - `docs/maester-parity.md`
  - `.github/carl/memory.md`
  - `.github/carl/current-pr-contract.md`

## Excluded
- New collectors or Graph endpoint additions.
- New checks unless strictly required for result/detail plumbing.
- Full Markdown/HTML per-principal evidence tables.
- SARIF source locations or full tenant evidence dumps.
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
