# STANCE Maester parity roadmap

## Clean-room statement

STANCE uses Maester as a functional reference for feature areas, user outcomes, and coverage planning only.

Parity in this document means **equivalent operator outcomes**, not copied implementation. STANCE does not copy Maester source code, test bodies, rule wording, remediation text, report templates, or implementation structure.

## STANCE current state

- Runtime is 100% Go and provider-oriented.
- Core architecture is provider-neutral under `internal/core/*`.
- Microsoft 365 implementation lives under `internal/provider/microsoft365/*`.
- Current coverage is Entra Conditional Access checks with collect-once/evaluate-locally behavior.
- Existing check outputs are JSON, Markdown, JUnit, HTML, and SARIF.

## Planned parity milestones

### P0: Provider architecture and core CLI
- Keep provider-neutral core and canonical `microsoft365` provider naming.
- Maintain direct-API-only and no-PowerShell constraints.

### P1: Reporting parity foundation
- Provider/suite/check metadata registry.
- Discovery commands (`providers`, `suites`, `checks`).
- HTML report output from `stance check`.

### P2: Microsoft 365 collector expansion
- Add new direct API collectors for additional Microsoft 365 workloads.

### P3: Baseline/suite expansion
- Expand built-in suites and checks across major baseline categories.

### P4: CI/CD packaging and GitHub Action
- Deliver action-ready packaging and workflow guidance for CI execution.

### P5: Drift history and notifications
- Add longitudinal run history, drift comparison, and notification hooks.

### P6: Custom rule packs
- Support custom checks and external rule packs without breaking core guardrails.

### P7: Conditional Access What-If style analysis
- Add deeper scenario analysis aligned to Conditional Access planning workflows.

## Explicit non-goals for this phase

- Full Maester parity in one PR.
- New Microsoft API collectors in this PR.
- New posture checks in this PR (except test-only scaffolding if required).
- Released-binary install mode for GitHub Action execution in this PR.
- Built-in GitHub OIDC-to-Entra token exchange implementation in this PR.

## Parity status values

This matrix uses only these status values:

- `not-started`
- `partial`
- `implemented`
- `deferred`

## Feature area inventory and parity matrix

| Area | Maester capability | STANCE current | STANCE target | Status | Notes |
| --- | --- | --- | --- | --- | --- |
| Provider architecture and core CLI | Stable operator experience across execution surfaces | Provider-neutral core and Microsoft 365 provider routing are in place | Preserve and extend this architecture as parity work scales | implemented | This is the foundation parity layer for all later milestones |
| Built-in Microsoft 365 security tests | Broad Microsoft 365 test catalog across workloads | Initial Entra CA checks only | Expand collectors and rule coverage incrementally | partial | Outcome parity planned through staged collector and suite growth |
| Multiple compliance/baseline suites | Multiple baseline/compliance-aligned groupings | Single `entra` suite currently implied by rules | Expand to multiple suites and mapped baselines | partial | P3 focus |
| Custom tests | User-defined tests and extension model | Not available | Custom rule packs and user-authored checks | not-started | P6 focus |
| CI/CD execution | Native CI usage patterns | Composite GitHub Action wrapper available (local-build mode) | Expand install modes and deeper automation | partial | Initial wrapper and workflow guidance are implemented; release-binary mode remains future work |
| Rich reporting | Human-readable and machine-readable reports | JSON/Markdown/JUnit/HTML/SARIF via check/report | Continue improving integrations and operator UX | implemented | Durable result JSON plus offline conversion is in place |
| Notifications | Alerting and operational notification flows | Not available | Post-run notifications with drift context | not-started | P5 focus |
| GitHub Actions / Azure DevOps integration | Turnkey pipeline integration | Initial GitHub Action wrapper and examples/docs available | Expand beyond initial GitHub local-build flow and document additional execution surfaces | partial | SARIF upload path is documented; release-binary mode and deeper auth automation remain future work |
| Workload identity federation | Secure non-secret execution paths | WIF-first auth shape already in place | Keep WIF-first and strengthen CI packaging | partial | Continue hardening with P4 |
| Continuous monitoring / drift detection | Scheduled monitoring and change awareness | Point-in-time execution only | Scheduled runs, history, and drift signals | not-started | P5 focus |
| Admin-facing remediation guidance | Rich remediation-oriented guidance | Minimal check metadata and summaries | Expand guidance while keeping clean-room wording | partial | Expand gradually with suite growth |
| Conditional Access What-If style analysis | What-if planning style workflows | Not available | Add analysis features for CA scenario outcomes | not-started | P7 focus |
| Test install/update lifecycle | Install/update experience for tests/content | Not available | Introduce controlled rule pack lifecycle | deferred | Revisit after core custom-pack capability stabilizes |
