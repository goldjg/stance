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
- This PR intentionally adds no new Microsoft API collectors and no new posture checks.
