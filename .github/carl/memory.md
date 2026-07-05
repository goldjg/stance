# cARL memory

## Project identity
- Name: STANCE (Secure Tenant And Configuration Evaluator).
- Runtime: 100% Go.
- Mission: Microsoft 365 posture evaluation through direct API collection and local rule evaluation.

## Durable constraints
- Do not introduce PowerShell runtime dependencies.
- Do not use Microsoft PowerShell modules.
- Do not shell out to `pwsh`, `az`, `mggraph`, Graph CLI, or M365 admin modules.
- Prefer direct Microsoft Graph/ARM/service REST APIs.
- Keep dependency footprint small and justified.
- OIDC/workload identity federation first; client secrets only as documented fallback.
- Collector-first architecture: collect once, evaluate many.

## Clean-room rule
- Maester is reference-only for coverage and UX direction.
- Do not copy Maester code, test bodies, wording, remediation text, or report text.
- Record inspiration as coverage comparison only.

## Delivery rule
- Keep PRs small, focused, and reviewable.
- Log API uncertainty as explicit research items instead of assumptions.

## Implemented decisions
- `stance auth test` uses environment-driven configuration and fails closed on ambiguous auth material.
- Workload identity assertion (`STANCE_CLIENT_ASSERTION` or `STANCE_FEDERATED_TOKEN_FILE`) is preferred over secrets in examples.
- Auth error output must pass through redaction before reaching CLI stderr.
- `stance collect` produces a normalized fact bundle (organization + conditional access) for local evaluation.
- `stance check` evaluates built-in CA posture rules from facts without live API calls.
- `stance explain --check <id>` returns machine-readable metadata for implemented checks.
- High-signal CA rules include privileged-role targeting, MFA enforcement gaps, and emergency access exclusion gaps.
