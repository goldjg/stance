# STANCE GitHub Action (initial)

## Purpose

The STANCE GitHub Action provides a repository-local wrapper for running posture
evaluation in GitHub Actions using the STANCE CLI from this repository.

## Current status

This is the initial implementation:

- Composite action at repository root (`action.yml`)
- Builds `stance` locally from checked-out source
- Runs collect/check/report flow for `microsoft365`
- Supports facts-only evaluation without Microsoft authentication

Released-binary install mode is planned but not included in this version.

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

## Live collection example

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

  - name: Exchange GitHub OIDC token for Entra federated assertion/token file
    run: |
      echo "Implement your OIDC token exchange here."

  - name: Run STANCE
    id: stance
    uses: ./
    with:
      provider: microsoft365
      suite: entra
      formats: json,html,sarif
      output-directory: stance-results
    env:
      STANCE_TENANT_ID: ${{ vars.STANCE_TENANT_ID }}
      STANCE_CLIENT_ID: ${{ vars.STANCE_CLIENT_ID }}
      STANCE_FEDERATED_TOKEN_FILE: ${{ env.STANCE_FEDERATED_TOKEN_FILE }}
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

When `facts-path` is provided, the action skips live collection and does not
require Microsoft authentication material.

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

## Authentication

STANCE currently expects environment-driven auth material for live collection.

Preferred (WIF-first) variables:

- `STANCE_TENANT_ID`
- `STANCE_CLIENT_ID`
- `STANCE_FEDERATED_TOKEN_FILE` or `STANCE_CLIENT_ASSERTION`

Current limitation:

- The action does not implement GitHub OIDC-to-Entra token exchange.
- You must perform this exchange in your workflow before invoking STANCE.

Fallback (less preferred):

- `STANCE_CLIENT_SECRET` may be used for client-secret auth where needed.

## Permissions

GitHub workflow permissions for typical security integration:

- `contents: read`
- `id-token: write` (required for WIF token exchange flows)
- `security-events: write` (required for SARIF upload)

Microsoft Graph permissions currently required for `entra` suite collection:

- `Organization.Read.All`
- `Policy.Read.All`

## Security notes

- Generated facts, results, and report artifacts may contain sensitive tenant
  posture information.
- Avoid long-lived/public artifact retention for sensitive tenants.
- Do not echo secrets or token material in workflow logs.
- STANCE SARIF output represents tenant posture findings, not source-code
  location vulnerabilities.

## Future work

- Released-binary install mode for action execution.
- Optional built-in helper for GitHub OIDC-to-Entra exchange flow.
- `fail-on-findings` behavior support.
- Scheduled drift comparison and historical run analysis patterns.
