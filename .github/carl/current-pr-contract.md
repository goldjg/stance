# Current PR contract

## PR focus
Initial bootstrap implementation covering PR1-PR7 foundation work in one delivery slice for review tightening.

## Included
- Go module initialization.
- CLI surface with implemented `version`, `init`, `auth test`, `collect`, `check`, `permissions`, `explain`.
- Provider-oriented architecture split:
  - provider-neutral core packages under `internal/core/*`
  - Microsoft 365 provider packages under `internal/provider/microsoft365/*`
- cARL governance bootstrap in `.github/carl/`.
- README project thesis, hard constraints, non-goals.
- GitHub Actions CI with gofmt/test/vet.
- Auth provider skeleton (WIF-first with fallback secret flow) and redaction behavior.
- Graph and HTTP client foundations (retry, retry-after, user-agent, pagination).
- Collector-first fact bundle and initial Conditional Access collection.
- Initial evaluator and JSON/Markdown/JUnit report rendering via `check --format`.

## Excluded
- Remediation/write actions.
- Standalone `stance report` conversion command.
- SARIF output (planned).

## Guardrails
- Keep changes minimal and reviewable.
- Preserve clean-room constraints.
- Keep dependencies minimal.
