# Copilot instructions for STANCE

- This repository is Go-native and direct-API-first.
- Keep core architecture provider-neutral; place Microsoft-specific logic under `internal/provider/microsoft365`.
- Do not add PowerShell runtime/module dependencies.
- Do not shell out to `pwsh`, `az`, `mggraph`, or Graph CLI.
- Follow collector-first architecture and avoid repeated API calls per check.
- Keep dependencies minimal and justified.
- Keep PRs small and focused.
- Treat Maester as functional reference only; do not copy implementation/text.
