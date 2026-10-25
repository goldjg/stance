# Current PR contract

## Status and goal

Complete implementation and available local validation: migrate source, CI,
and release builds to Go 1.26.10 for
CVE-2026-111943 and earlier standard-library security fixes.
This contract supersedes the completed collection-completeness scope.
The branch starts from merged PR #16, including its Graph regression tests.

## Approved scope and affected files

- `go.mod`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, and
  `.goreleaser.yaml`: patch-level compiler selection, verification, and
  fail-closed release builds.
- `README.md`, `DISTRIBUTION.md`, `docs/github-action.md`, this contract, and
  `.github/carl/memory.md`: current source requirements and release guidance.
- Separate focused branch, commit, push, and pull request.

## Non-goals and forbidden scope

- No unrelated dependency upgrades, runtime changes, new providers, API
  endpoints, permissions, authentication changes, or report schema changes.
- No release publication, tag creation, PR merge, secret/settings changes,
  system-wide tool installation, or cloud-resource mutation.
- No PowerShell/module/SDK runtime dependencies or CLI shell-outs.

## Plan and constraints

1. Verify PR #16 ancestry and audit declarations, workflows, packaging, and
   published compiler provenance.
2. Require Go 1.26.10 in source; pin and verify CI/release compilers and disable
   implicit switching in packaging.
3. Validate tests, vet, formatting, vulnerabilities, and all five release
   targets; inspect embedded compiler metadata.
4. Reconcile documentation and submit without publishing.

Preserve provider-neutral core, direct read-only APIs, static packaging,
existing targets/build flags, and signing/publishing semantics.
Use patched Go 1.26 rather than 1.27 by explicit user choice to retain macOS 12
support; document modern Go's OS minimums rather than promising Go 1.19's.

## Contract assertions and validation

1. Source builds reject an older local compiler; CI/release use the pinned
   patch, not runner defaults (`GOTOOLCHAIN=local` and compiler assertion).
2. PR #16 pagination and redirect regressions pass with `go test ./...`;
   `go vet ./...` and `gofmt -l .` remain clean.
3. GoReleaser config validation and non-publishing snapshot build produce all
   five existing targets and native Linux packages with Go 1.26.10.
4. `go mod tidy` introduces no dependencies; `govulncheck` checks the new
   source and `go version -m` distinguishes newly built and published binaries.

Validate workflow syntax and `git diff --check`. Report native-platform,
signing, publication, or vulnerability-check gaps explicitly.

## Risks, stop conditions, and reconciliation

Stop on incompatible runtime behaviour, required target removal, unrelated
module churn, conflicting local work, or any need to publish/change secrets.
Cross-compilation does not prove native macOS/Windows execution or signing.
Older installed binaries remain unchanged until replaced.

Update distribution/source-build guidance and durable compiler-policy memory;
do not change invariants, provider trust boundaries, or historical test code.

## Validation outcome and reset

Tidy added no dependencies. Formatting, full tests (including PR #16 Graph
regressions), vet, workflow syntax, GoReleaser v2.16.0 check/snapshot, source
and binary vulnerability scans, and older-compiler rejection checks passed.
All five snapshot binaries embed Go 1.26.10; all six Linux packages and archive
checksums passed validation. Both macOS binaries declare minimum macOS 12.0.
Linux deb payloads match their corresponding snapshot binaries.

Native macOS/Windows execution and signing/publication were not performed.
No GitHub Releases existed during the audit. PR/hosted-check state belongs
in the PR, not this completed scope; future work must establish a new contract.
