# cARL memory

## Project identity
- Name: STANCE (Secure Tenant And Configuration Evaluator).
- Runtime: 100% Go.
- Mission: provider-oriented posture evaluation through direct API collection and local rule evaluation.
- STANCE is the generic product/CLI identity; `microsoft365` is the first provider, not part of the product name.

## Durable constraints
- Do not introduce PowerShell runtime dependencies.
- Do not use Microsoft PowerShell modules.
- Do not shell out to `pwsh`, `az`, `mggraph`, Graph CLI, or Microsoft 365 admin modules.
- Prefer direct Microsoft Graph/ARM/service REST APIs.
- Keep dependency footprint small and justified.
- OIDC/workload identity federation first; client secrets only as documented fallback.
- Collector-first architecture: collect once, evaluate many.

## Clean-room rule
- Maester is reference-only for Microsoft 365 coverage and UX direction.
- Do not copy Maester code, test bodies, wording, remediation text, or report text for the Microsoft 365 provider.
- Record inspiration as coverage comparison only.

## Delivery rule
- Keep PRs small, focused, and reviewable.
- Log API uncertainty as explicit research items instead of assumptions.

## Implemented decisions
- STANCE core remains provider-neutral; Microsoft-specific logic must stay under `internal/provider/microsoft365`.
- Canonical internal provider name is `microsoft365`; aliases like `m365` are deferred.
- Core packages must not accumulate Microsoft-specific assumptions (Graph endpoints, Entra suite IDs, or Microsoft permission names).
- `stance auth test` uses environment-driven configuration and fails closed on ambiguous auth material.
- Workload identity assertion (`STANCE_CLIENT_ASSERTION` or `STANCE_FEDERATED_TOKEN_FILE`) is preferred over secrets in examples.
- Auth error output must pass through redaction before reaching CLI stderr.
- `stance collect` produces a normalized fact bundle (organization + conditional access) for local evaluation.
- `stance check` evaluates built-in CA posture rules from facts without live API calls.
- `stance explain --check <id>` returns machine-readable metadata for implemented checks.
- CA authentication strength evidence is mapped from `grantControls.authenticationStrength` (not `sessionControls`).
- Excluded users in CA policies are treated as informational-only evidence and do not prove emergency-access coverage.
- STANCE has a documented Maester parity roadmap in `docs/maester-parity.md`.
- Parity is defined as equivalent user outcomes, not copied implementation lineage.
- Provider/suite/check catalog metadata is the discovery foundation for future parity milestones.
- HTML output for `stance check --format html` is the first reporting parity slice.
- `stance report` is implemented as an offline result conversion command from durable STANCE result JSON.
- `stance check --format json` emits the durable STANCE result document as handoff format to `stance report`.
- SARIF output (`--format sarif`) is implemented for both `stance check` and `stance report`.
- STANCE release packaging uses GoReleaser v2 with project-specific release/distribution configuration.
- Tagged `v*` releases publish cross-platform STANCE CLI artefacts (linux/darwin/windows amd64, plus linux/darwin arm64).
- Linux native packages (`deb`, `rpm`, `apk`) are generated via GoReleaser nFPM config.
- Homebrew cask publishing targets `goldjg/homebrew-stance` via `HOMEBREW_TAP_GITHUB_TOKEN`.
- WinGet submission is optional and token-gated via release workflow (`WINGETCREATE_TOKEN`) using package ID `goldjg.STANCE`.
- macOS release artefacts are codesigned when Apple signing secrets are configured.
- Notarisation is not implemented yet; darwin artefacts are signed but not notarised.
- Initial STANCE GitHub Action wrapper exists as a repository-local composite action (`action.yml`) that builds STANCE from checked-out source.
- The GitHub Action supports facts-only mode via `facts-path` and can run evaluation/report generation without Microsoft authentication.
- The GitHub Action supports `auth-mode: env` for explicit caller-provided Microsoft auth variables.
- The GitHub Action supports `auth-mode: github-oidc` and can acquire a GitHub OIDC token for live collection.
- In `github-oidc` mode, the action passes the GitHub OIDC assertion to STANCE via `STANCE_CLIENT_ASSERTION`.
- Entra federated identity credential setup remains external to STANCE and must not be faked.
- SARIF upload is supported by generating `stance.sarif` and uploading through `github/codeql-action/upload-sarif`.
- Facts-only mode remains auth-free.
- The GitHub Action supports `stance-version: local`, `latest`, and explicit `vX.Y.Z` tags.
- Released-binary action mode downloads GitHub Release archives and verifies SHA-256 against release `checksums.txt` before extraction/execution.
- Pinned explicit versions are recommended for production workflows; `latest` is convenience mode and less deterministic.
- Auth modes `env` and `github-oidc` remain supported after install-mode expansion.
- Microsoft 365 collector scope now includes Entra directory role definitions and role assignments via direct Graph API.
- Privileged principals are derived from Entra role assignments as facts for future coverage analysis.
- ENTRA role visibility checks are informational/cautious and do not claim emergency-access or break-glass pass/fail outcomes.
- `RoleManagement.Read.Directory` is required for directory role assignment collection; `Directory.Read.All` may be required for principal detail resolution.
- This collector expansion adds no PowerShell/runtime/module dependencies, no shell-outs, and no Microsoft SDK dependency.
