# Current PR contract

## PR focus
Add first-class STANCE release and distribution packaging.

## Included
- Add `.goreleaser.yaml` with STANCE-specific release configuration.
- Add `.github/workflows/release.yml` tag-triggered release workflow.
- Add `.github/scripts/codesign-darwin.sh` darwin codesign helper.
- Configure native Linux package generation (`deb`, `rpm`, `apk`) via nFPM.
- Configure Homebrew cask publishing target for `goldjg/homebrew-stance`.
- Add optional token-gated WinGet submission job in release workflow.
- Add `DISTRIBUTION.md` release/distribution documentation.
- Update README release/install guidance and link distribution docs.
- Update `.github/carl/memory.md` with durable release packaging truth.

## Excluded
- New Microsoft API collectors.
- New posture checks.
- New providers.
- GitHub Action wrapper for running STANCE posture commands.
- macOS notarisation implementation.
- Live release publishing verification against external channels.

## Guardrails
- Keep STANCE runtime 100% Go.
- No PowerShell runtime/module dependency in STANCE CLI runtime.
- No shell-out from STANCE CLI runtime to `pwsh`, `az`, `mggraph`, Graph CLI, or Microsoft admin modules.
- Preserve provider-neutral core architecture and canonical `microsoft365` provider usage.
- Keep dependency footprint minimal and justified.
- Keep clean-room Maester boundaries.

## Validation requirements
- `gofmt -l .` clean.
- `go test ./...`.
- `go vet ./...`.
- `goreleaser check` when available in environment.
