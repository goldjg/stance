# STANCE (Secure Tenant And Configuration Evaluator)

STANCE is a fast, Go-native security posture evaluator framework.

STANCE uses a provider-oriented architecture: core command/report/evaluation concepts stay provider-neutral, while provider-specific collection and checks live in provider packages.

The first provider is `microsoft365`. It talks directly to Microsoft APIs, collects tenant facts once, evaluates checks locally, and emits CI-friendly reports without PowerShell runtime/module dependencies.

Repository canonical location: `goldjg/stance`.

## Project thesis

STANCE pursues Maester-shaped outcomes, but not Maester-shaped implementation.

- Maester is a functional reference for Microsoft 365 problem space and coverage ideas.
- STANCE is clean-room implementation and must not copy Maester source code, rule text, implementation structure, or report text.
- Parity means equivalent operator outcomes, not copied implementation.

Roadmap: [Maester parity roadmap](docs/maester-parity.md).

## v0.1 scope

- Provider support: `microsoft365` only for now.
- Microsoft 365 scope: Entra ID and Conditional Access only.
- Read-only posture assessment.
- Current check output formats: JSON, Markdown summary, JUnit XML.
- Current discovery commands: `providers`, `suites`, `checks`.
- Planned output: SARIF and standalone `stance report`.

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
- `stance providers`
- `stance suites`
- `stance checks`
- `stance report`

`stance report` is planned and not yet implemented as a standalone conversion command.

Provider-aware commands currently default to `--provider microsoft365`:

- `stance collect --provider microsoft365`
- `stance check --provider microsoft365`
- `stance permissions --provider microsoft365 --suite entra`
- `stance explain --provider microsoft365 --check ENTRA-CA-001`
- `stance suites --provider microsoft365`
- `stance checks --provider microsoft365 --suite entra`

Provider discovery command:

- `stance providers`

Check discovery JSON output:

- `stance checks --provider microsoft365 --suite entra --format json`

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

`stance check` evaluates collected facts with provider rules:

- `ENTRA-CA-001` disabled Conditional Access policies detected.
- `ENTRA-CA-002` report-only Conditional Access policies detected.

Supported formats right now:

- `json`
- `md` / `markdown`
- `junit`
- `html`

HTML report example:

- `stance check --facts facts.json --format html --out report.html`

Additional implemented checks:

- `ENTRA-CA-003` privileged-role-targeted Conditional Access policies identified.
- `ENTRA-CA-004` privileged-role-targeted policies missing MFA/auth strength enforcement.
- `ENTRA-CA-005` privileged-role-targeted policies with user exclusions observed (informational only; not proof of emergency access coverage).