# STANCE GitHub Action

## Purpose

The STANCE GitHub Action is a composite action that installs the STANCE CLI,
then runs collect/check/report in CI.

Reference example workflow files:

- `docs/examples/github-actions/stance-microsoft365.yml`
- `docs/examples/github-actions/stance-facts-only.yml`

## Current status

- Composite action at repository root (`action.yml`)
- Install modes via `stance-version`:
  - `local` (build from checked-out source)
  - `latest` (download latest GitHub Release asset)
  - `vX.Y.Z` (download pinned release asset)
- Released-binary mode verifies archive SHA-256 against release `checksums.txt`
  before extraction and execution
- Live collection and facts-only evaluation paths
- Action-native optional GitHub OIDC assertion acquisition for live collection

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `provider` | `microsoft365` | STANCE provider to evaluate. |
| `suite` | `entra` | STANCE suite to evaluate. |
| `output-directory` | `stance-results` | Directory for generated facts, result JSON, and reports. |
| `formats` | `json,html,sarif` | Comma-separated report formats to generate (`json`, `html`, `sarif`, `md`/`markdown`, `junit`). |
| `facts-path` | `""` | Existing facts JSON to evaluate instead of live collection. |
| `auth-mode` | `env` | Live-collection auth source: `env` or `github-oidc`. |
| `oidc-audience` | `api://AzureADTokenExchange` | Audience value used when requesting GitHub OIDC token in `github-oidc` mode. |
| `tenant-id` | `""` | Optional tenant ID exported as `STANCE_TENANT_ID` when set. |
| `client-id` | `""` | Optional client/application ID exported as `STANCE_CLIENT_ID` when set. |
| `stance-version` | `local` | STANCE install mode: `local`, `latest`, or pinned tag such as `v0.1.0`. |
| `fail-on-findings` | `false` | Reserved for future behavior; not implemented in this version. |

## `stance-version` modes

- `local`
  - Builds from checked-out repository source.
  - Intended for repository development and dogfooding (`uses: ./`).
- `latest`
  - Resolves the latest STANCE GitHub Release tag.
  - Downloads matching release archive for the runner platform.
  - Convenient, but less deterministic over time.
- `vX.Y.Z`
  - Uses a specific release tag (for example `v0.1.0`).
  - Downloads matching release archive for that exact release.
  - Recommended for production workflows.

For production workflows, pin both:

- action ref (for example `uses: goldjg/stance@v0.1.0`)
- `stance-version` (for example `stance-version: v0.1.0`)

## Release asset mapping

Release tag keeps the `v` prefix (for example `v0.1.0`) while archive filenames
use the bare version (for example `0.1.0`):

- tag: `v0.1.0`
- asset version: `0.1.0`
- asset format: `stance_<asset-version>_<os>_<arch>.<ext>`

Supported released-binary runner targets:

| Runner target | Asset name pattern |
| --- | --- |
| Linux x64 | `stance_<version>_linux_amd64.tar.gz` |
| Linux arm64 | `stance_<version>_linux_arm64.tar.gz` |
| macOS x64 | `stance_<version>_darwin_amd64.tar.gz` |
| macOS arm64 | `stance_<version>_darwin_arm64.tar.gz` |
| Windows x64 | `stance_<version>_windows_amd64.zip` |

Unsupported targets fail clearly in released-binary mode.

## Checksum verification

Released-binary mode always downloads both:

- selected release archive
- `checksums.txt` from the same release tag

The action then:

1. Confirms the selected archive basename exists in `checksums.txt`.
2. Computes archive SHA-256 on the runner.
3. Fails if checksum is missing or mismatched.
4. Extracts and executes only after checksum verification succeeds.

## Authentication modes

### `auth-mode: env`

Use caller-provided environment auth variables for live collection.

- The action does not fetch GitHub OIDC tokens in this mode.
- Existing auth variables remain caller-controlled.
- If `tenant-id`/`client-id` inputs are set, they are exported to
  `STANCE_TENANT_ID`/`STANCE_CLIENT_ID`.
- Live collection can use:
  - `STANCE_CLIENT_ASSERTION`, or
  - `STANCE_FEDERATED_TOKEN_FILE`, or
  - `STANCE_CLIENT_SECRET` (fallback).

### `auth-mode: github-oidc`

Use GitHub's OIDC endpoint in the action to acquire a short-lived assertion and
export it as `STANCE_CLIENT_ASSERTION` for live collection.

- Requires workflow permission `id-token: write`.
- Uses `oidc-audience` input when requesting the token.
- Masks assertion material in logs and avoids token echoing.
- If `tenant-id`/`client-id` inputs are set, they are exported for STANCE.

When `facts-path` is provided, live collection is skipped and OIDC acquisition
is skipped regardless of auth mode.

Facts-only mode remains auth-free.

## Local dogfooding example (`uses: ./`)

```yaml
permissions:
  contents: read
  id-token: write
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-go@v5
    with:
      go-version-file: go.mod

  - name: Run STANCE from local source
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

## External repository production-style example (pinned)

```yaml
permissions:
  contents: read
  id-token: write
  security-events: write

steps:
  - name: Run STANCE (pinned action + pinned binary)
    id: stance
    uses: goldjg/stance@v0.1.0 # Example tag placeholder; pin to a real release tag.
    with:
      stance-version: v0.1.0
      auth-mode: github-oidc
      tenant-id: ${{ vars.STANCE_TENANT_ID }}
      client-id: ${{ vars.STANCE_CLIENT_ID }}
      provider: microsoft365
      suite: entra
      formats: json,html,sarif
      output-directory: stance-results
```

## Facts-only example

Facts-only mode can use either local or released-binary install mode.

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-go@v5
    with:
      go-version-file: go.mod

  - name: Run STANCE from existing facts
    id: stance
    uses: ./
    with:
      stance-version: local
      provider: microsoft365
      suite: entra
      facts-path: examples/facts/sample-facts.json
      formats: json,html,sarif
      output-directory: stance-results
```

Equivalent released-binary mode:

```yaml
- name: Run STANCE from existing facts (pinned release binary)
  id: stance
  uses: goldjg/stance@v0.1.0 # Example tag placeholder; pin to a real release tag.
  with:
    stance-version: v0.1.0
    provider: microsoft365
    suite: entra
    facts-path: examples/facts/sample-facts.json
    formats: json,html,sarif
    output-directory: stance-results
```

## Entra setup requirements (external to STANCE)

`auth-mode: github-oidc` does not create Microsoft trust configuration.
You must configure this externally:

- An Entra app registration/service principal
- A federated identity credential that trusts the GitHub
  repository/ref/environment
- Microsoft Graph application permissions required by selected STANCE suite

For current `entra` suite collection:

- `Organization.Read.All`
- `Policy.Read.All`

## SARIF upload guidance

Use GitHub's SARIF uploader with the action output:

```yaml
- name: Upload SARIF
  if: ${{ steps.stance.outputs.sarif-path != '' }}
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.stance.outputs.sarif-path }}
```

## Artifact upload guidance

Upload output files using `actions/upload-artifact`:

```yaml
- name: Upload STANCE artifacts
  uses: actions/upload-artifact@v4
  with:
    name: stance-results
    path: |
      ${{ steps.stance.outputs.facts-path }}
      ${{ steps.stance.outputs.results-path }}
      ${{ steps.stance.outputs.html-path }}
      ${{ steps.stance.outputs.sarif-path }}
      ${{ steps.stance.outputs.markdown-path }}
      ${{ steps.stance.outputs.junit-path }}
```

## Security notes

- Released binaries are checksum-verified before extraction and execution.
- GitHub OIDC tokens are short-lived; prefer this over long-lived secrets when
  feasible.
- Do not echo assertions/tokens in workflow logs.
- Prefer repo/environment-scoped Entra federated credentials.
- Avoid broad branch/ref patterns in federated credential trust when possible.
- Generated facts/results/reports can contain sensitive tenant posture data.
- STANCE SARIF output represents tenant posture findings, not source-code
  location vulnerabilities.
