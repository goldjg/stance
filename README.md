# STANCE (Secure Tenant And Configuration Evaluator)

STANCE is a fast, Go-native security posture evaluator framework.

STANCE uses a provider-oriented architecture: core command/report/evaluation concepts stay provider-neutral, while provider-specific collection and checks live in provider packages.

The first provider is `microsoft365`. It talks directly to Microsoft APIs, collects tenant facts once, evaluates checks locally, and emits CI-friendly reports without PowerShell runtime/module dependencies.

Repository canonical location: `goldjg/stance`.
Repository rename note: historical references to `goldjg/stance-365` should be treated as legacy and migrated to `goldjg/stance`.

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
- Current check output formats: durable result JSON, Markdown summary, JUnit XML, HTML, SARIF.
- Current discovery commands: `providers`, `suites`, `checks`.
- Standalone `stance report` converts durable result JSON into report formats offline.

## Hard constraints

- 100% Go runtime code.
- Keep STANCE core provider-neutral; provider-specific assumptions belong in `internal/provider/<name>`.
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

`stance report` is implemented as a standalone offline conversion command.

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

## Release and installation

STANCE release/distribution packaging is configured for tagged releases (`v*`)
when required secrets and repositories are present.

- Direct release downloads: GitHub Releases for `goldjg/stance`
- Distribution guide (artefacts, checksums, Linux packages, Homebrew, WinGet):
  [DISTRIBUTION.md](DISTRIBUTION.md)
- Homebrew configured path:
  - `brew tap goldjg/stance`
  - `brew trust goldjg/stance`
  - `brew install --cask stance`
- WinGet configured path (token-gated workflow submission):
  - `winget install goldjg.STANCE`

Build from source:

```sh
go install github.com/goldjg/stance/cmd/stance@latest
```

Runtime constraints remain unchanged: STANCE runtime is 100% Go, provider-core
boundaries remain provider-neutral, and STANCE does not add PowerShell runtime
or Microsoft module dependencies.

## GitHub Action (initial)

STANCE now includes an initial composite GitHub Action wrapper at repository
root (`action.yml`) that builds STANCE locally from checked-out source.

- Documentation: [docs/github-action.md](docs/github-action.md)
- Current mode: local build only (`stance-version: local`)
- Planned: released-binary action install mode

Minimal invocation example:

```yaml
- name: Run STANCE
  id: stance
  uses: ./
  with:
    provider: microsoft365
    suite: entra
    formats: json,html,sarif
    output-directory: stance-results
```

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
- `sarif`

Durable result document generation:

- `stance check --facts facts.json --format json --out results.json`

HTML report example:

- `stance check --facts facts.json --format html --out report.html`

SARIF report example:

- `stance check --facts facts.json --format sarif --out stance.sarif`

Offline conversion examples:

- `stance report --results results.json --format html --out report.html`
- `stance report --results results.json --format sarif --out stance.sarif`

Suggested CI flow:

1. collect facts (`stance collect --out facts.json`)
2. evaluate checks to durable results (`stance check --facts facts.json --format json --out results.json`)
3. convert results to presentation and integration outputs (`stance report --results results.json --format html --out report.html` and `stance report --results results.json --format sarif --out stance.sarif`)

Additional implemented checks:

- `ENTRA-CA-003` privileged-role-targeted Conditional Access policies identified.
- `ENTRA-CA-004` privileged-role-targeted policies missing MFA/auth strength enforcement.
- `ENTRA-CA-005` privileged-role-targeted policies with user exclusions observed (informational only; not proof of emergency access coverage).