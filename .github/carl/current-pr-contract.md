# Current PR contract

  ## PR focus
  Add collection completeness/readiness signalling for current Microsoft 365 Entra checks.

  ## Included
  - Add Microsoft 365 completeness summary helper under `internal/provider/microsoft365/eval` derived from existing fact families only.
  - Add informational check `ENTRA-COLLECT-001` for collection completeness/readiness evidence.
  - Add machine-readable finding details under `details.collection_completeness`.
  - Keep check/report compatibility across JSON, Markdown, HTML, JUnit, and SARIF outputs.
  - Add/adjust tests for completeness status derivation, catalog/listing presence, JSON details payload, and output compatibility.
  - Update docs and governance artifacts:
    - `README.md`
    - `docs/maester-parity.md`
    - `.github/carl/memory.md`
    - `.github/carl/current-pr-contract.md`

  ## Excluded
  - New Graph collectors or Graph endpoints.
  - Full Markdown/HTML per-principal evidence tables or tenant evidence dumps.
  - SARIF source locations or full tenant evidence dumps.
  - Nested/transitive group expansion.
  - Dynamic group rule evaluation.
  - Emergency-access/break-glass pass/fail logic.
  - Full effective Conditional Access simulation or What-If parity.
  - Scoring system.
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
