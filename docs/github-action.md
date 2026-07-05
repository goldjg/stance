# STANCE GitHub Action

## Purpose

The STANCE GitHub Action is a repository-local composite action that builds and
runs STANCE from checked-out source.

## Current status

- Composite action at repository root (`action.yml`)
- Local build execution (`stance-version: local`) only
- Live collection and facts-only evaluation paths
- Action-native optional GitHub OIDC assertion acquisition for live collection

Released-binary install mode is still planned and not implemented yet.

Reference example workflow files:

- `docs/examples/github-actions/stance-microsoft365.yml`
- `docs/examples/github-actions/stance-facts-only.yml`

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
| `stance-version` | `local` | Version source. Only `local` is currently supported. |
| `fail-on-findings` | `false` | Reserved for future behavior; not implemented in this version. |

## Outputs

| Output | Description |
| --- | --- |
| `facts-path` | Facts path used for evaluation (provided input path or generated facts path). |
| `results-path` | Durable STANCE result JSON path (`<output-directory>/results.json`). |
| `html-path` | HTML report path when `html` is requested. |
| `sarif-path` | SARIF report path when `sarif` is requested. |
| `markdown-path` | Markdown report path when `md` or `markdown` is requested. |
| `junit-path` | JUnit XML report path when `junit` is requested. |

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

Unsupported `auth-mode` values fail clearly.

If `auth-mode: github-oidc` is selected but GitHub OIDC request environment
variables are unavailable, the action fails with guidance to set
`permissions: id-token: write`.

## Live collection example (`github-oidc`)

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

  - name: Run STANCE
    id: stance
    uses: ./
    with:
      auth-mode: github-oidc
      tenant-id: ${{ vars.STANCE_TENANT_ID }}
      client-id: ${{ vars.STANCE_CLIENT_ID }}
      provider: microsoft365
      suite: entra
      formats: json,html,sarif
      output-directory: stance-results
```

## Facts-only example

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
      provider: microsoft365
      suite: entra
      facts-path: examples/facts/sample-facts.json
      formats: json,html,sarif
      output-directory: stance-results
```

Facts-only mode remains auth-free.

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

- GitHub OIDC tokens are short-lived; prefer this over long-lived secrets when
  feasible.
- Do not echo assertions/tokens in workflow logs.
- Prefer repo/environment-scoped Entra federated credentials.
- Avoid broad branch/ref patterns in federated credential trust when possible.
- Generated facts/results/reports can contain sensitive tenant posture data.
- STANCE SARIF output represents tenant posture findings, not source-code
  location vulnerabilities.

## Future work

- Released-binary install mode for action execution.
- `fail-on-findings` behavior support.
- Scheduled drift comparison and historical run analysis patterns.
