# Current PR contract

## PR focus
Add direct privileged-principal group membership facts and use them to improve cautious privileged-principal Conditional Access evidence.

## Included
- Add direct principal group membership fact model (`principal_group_memberships`) under Microsoft 365 provider facts.
- Add direct Graph collection for privileged principals using `directoryObjects/{id}/memberOf` (direct membership only).
- Reuse existing Conditional Access policy group targeting fields and correlate include/exclude group targets using direct membership evidence.
- Enhance privileged CA machine-readable details (`ENTRA-CA-006/007/008`) with deterministic direct group context:
  - `direct_group_ids`
  - `direct_group_display_names`
- Keep check/report compatibility across JSON, Markdown, HTML, JUnit, and SARIF outputs.
- Add/adjust tests for fact defaults, collector mapping/continuation, direct-group evidence correlation, and output compatibility.
- Update docs and governance artifacts:
  - `README.md`
  - `docs/maester-parity.md`
  - `.github/carl/memory.md`
  - `.github/carl/current-pr-contract.md`

## Excluded
- New checks unless strictly required for this direct-group evidence slice.
- Full Markdown/HTML per-principal evidence tables.
- SARIF source locations or full tenant evidence dumps.
- Graph transitive/nested group expansion.
- Dynamic group rule evaluation.
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
