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
- Microsoft 365 scope: Entra ID Conditional Access plus directory role definition/assignment collection and direct privileged-principal group membership collection for cautious privileged-principal CA evidence correlation.
- Direct privileged-principal group membership collection now records per-principal resolution status so STANCE can distinguish "no direct groups observed" from failed or unknown direct-group resolution.
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

## GitHub Action

STANCE includes a composite GitHub Action wrapper at repository root
(`action.yml`) that can build locally from source or install a released binary.

- Documentation: [docs/github-action.md](docs/github-action.md)
- Example workflow files:
  - `docs/examples/github-actions/stance-microsoft365.yml`
  - `docs/examples/github-actions/stance-facts-only.yml`
- Supported `stance-version` modes:
  - `local` (build from checked-out source)
  - `latest` (resolve and install latest release binary)
  - `vX.Y.Z` (install pinned release binary)
- Released-binary mode verifies release archive checksums before execution.
- For production workflows, pin both:
  - the action ref (for example `uses: goldjg/stance@v0.1.0`)
  - the binary version input (for example `stance-version: v0.1.0`)

Minimal `github-oidc` invocation example:

```yaml
- name: Run STANCE
  id: stance
  uses: ./
  with:
    stance-version: local
    auth-mode: github-oidc
    tenant-id: ${{ vars.STANCE_TENANT_ID }}
    client-id: ${{ vars.STANCE_CLIENT_ID }}
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
- `ENTRA-CA-006` privileged principal Conditional Access coverage evidence observed (informational visibility, not complete coverage proof).
- `ENTRA-CA-007` privileged principal direct/possible Conditional Access exclusion evidence observed (informational visibility, not emergency-access pass/fail).
- `ENTRA-CA-008` privileged principal Conditional Access coverage unknown from current facts (informational follow-up signal).
- `ENTRA-ROLE-001` privileged directory role assignments observed (informational visibility summary).
- `ENTRA-ROLE-002` privileged role assignments with incomplete principal details observed (informational caution).

STANCE now correlates privileged role-assignment facts, direct privileged-principal group memberships, and Conditional Access policy facts to produce cautious privileged-principal evidence. This evidence is intentionally not a full effective-policy proof.
Privileged-principal evidence now includes direct-group resolution status to avoid overclaiming when group lookup fails or resolution status is missing.

Durable result JSON now also carries optional structured finding details for privileged-principal CA evidence findings (`ENTRA-CA-006/007/008`) under `details.privileged_ca_evidence` for machine-readable handoff. Markdown, HTML, JUnit, and SARIF outputs remain summary-oriented and do not dump full per-principal evidence payloads.

Result JSON artifacts can include tenant posture and principal metadata (for example principal identifiers, display names, role names, direct group identifiers/names, direct-group resolution status, and observed policy identifiers).

Current limitations:

- Nested and transitive group expansion is not implemented.
- Dynamic group rule evaluation is not implemented.
- Emergency-access/break-glass account designation is not implemented.
- Full effective Conditional Access simulation (What-If style) is not implemented.
- Report-only policies are not treated as enforcement evidence.

## Microsoft Graph permissions (current)

- Conditional Access collection: `Organization.Read.All`, `Policy.Read.All`
- Directory role definition/assignment collection: `RoleManagement.Read.Directory`
- Principal detail and direct group membership enrichment: `Directory.Read.All` is required or may be required for principal/group detail resolution in some tenants