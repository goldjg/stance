# Trust boundaries

## Credential handling
- Never log access tokens or secrets.
- Redact sensitive auth fields in diagnostics.
- Fail closed on missing or ambiguous auth configuration.

## API interaction
- Use documented Microsoft REST endpoints.
- Treat unsupported/uncertain endpoints as research backlog items.

## Scope
- Read-only posture evaluation in v0.1.
- No write/remediation operations.
