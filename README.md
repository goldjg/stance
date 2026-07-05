# STANCE (Secure Tenant And Configuration Evaluator)

STANCE is a fast, Go-native Microsoft 365 security posture evaluator.

It talks directly to Microsoft APIs, collects tenant facts once, evaluates checks locally, and emits CI-friendly reports without PowerShell runtime/module dependencies.

## Project thesis

STANCE pursues Maester-shaped outcomes, but not Maester-shaped implementation.

- Maester is a functional reference for problem space and coverage ideas.
- STANCE is clean-room implementation and must not copy Maester source code, rule text, implementation structure, or report text.

## v0.1 scope

- Entra ID and Conditional Access only.
- Read-only posture assessment.
- Current check output formats: JSON, Markdown summary, JUnit XML.
- Planned output: SARIF.

## Hard constraints

- 100% Go runtime code.
- No PowerShell runtime dependency.
- No Microsoft PowerShell modules.
- No shelling out to `pwsh`, `az`, `mggraph`, ExchangeOnlineManagement, Teams modules, or Graph CLI.
- Direct APIs first (Graph REST, ARM REST, documented service REST endpoints where practical).
- OIDC/workload identity federation first; client secrets as fallback.
- Collect once, evaluate many.
- Single binary, container-friendly, CI/CD-first.
- Keep dependencies minimal and justified.

## Non-goals (v0.1)

- Full Maester parity.
- Exchange/Teams/Defender/SharePoint coverage.
- Remediation or write actions.
- Broad plugin architecture.

## Initial command surface

- `stance version`
- `stance init`
- `stance auth test`
- `stance collect`
- `stance check`
- `stance explain`
- `stance permissions`
- `stance report`

`stance report` is planned and not yet implemented as a standalone conversion command.

## Status

Repository bootstrap is in progress. The current milestone establishes:

- Go module and CLI skeleton.
- cARL governance bootstrap.
- Baseline CI for format/test/vet checks.

## Auth test command (current)

`stance auth test` validates token acquisition and performs a read-only Graph reachability check.

Required environment variables:

- `STANCE_TENANT_ID`
- `STANCE_CLIENT_ID`
- One of:
  - `STANCE_CLIENT_SECRET` (fallback path)
  - `STANCE_CLIENT_ASSERTION` (workload identity)
  - `STANCE_FEDERATED_TOKEN_FILE` (workload identity token file)

Optional:

- `STANCE_SCOPE` (defaults to `https://graph.microsoft.com/.default`)
- `STANCE_TOKEN_URL` (defaults to Entra v2 token endpoint for tenant)
- `STANCE_GRAPH_ORGANIZATION_URL` (defaults to Graph `/v1.0/organization?$top=1`)

Security posture:

- Auth config is fail-closed for missing or ambiguous credential inputs.
- Secrets and tokens are redacted from surfaced error strings.

## Check command (current)

`stance check` evaluates collected facts with built-in rules:

- `ENTRA-CA-001` disabled Conditional Access policies detected.
- `ENTRA-CA-002` report-only Conditional Access policies detected.

Supported formats right now:

- `json`
- `md` / `markdown`
- `junit`

Additional implemented checks:

- `ENTRA-CA-003` privileged-role-targeted Conditional Access policies identified.
- `ENTRA-CA-004` privileged-role-targeted policies missing MFA/auth strength enforcement.
- `ENTRA-CA-005` privileged-role-targeted policies with user exclusions observed (informational only; not proof of emergency access coverage).