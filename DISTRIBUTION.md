# STANCE Distribution Guide

This guide describes how STANCE release artefacts are packaged and distributed.
Distribution channels are configured for tagged releases when required secrets
and target repositories are present.

## Release artefacts

Every tagged release (`v*`) is configured to publish:

| Artefact | Platform |
|---|---|
| `stance_<version>_linux_amd64.tar.gz` | Linux x86-64 |
| `stance_<version>_linux_arm64.tar.gz` | Linux ARM64 |
| `stance_<version>_darwin_amd64.tar.gz` | macOS Intel |
| `stance_<version>_darwin_arm64.tar.gz` | macOS Apple Silicon |
| `stance_<version>_windows_amd64.zip` | Windows x86-64 |
| `stance_<version>_linux_amd64.deb` | Debian/Ubuntu |
| `stance_<version>_linux_arm64.deb` | Debian/Ubuntu ARM64 |
| `stance_<version>_linux_amd64.rpm` | Red Hat/Fedora |
| `stance_<version>_linux_arm64.rpm` | Red Hat/Fedora ARM64 |
| `stance_<version>_linux_amd64.apk` | Alpine |
| `stance_<version>_linux_arm64.apk` | Alpine ARM64 |
| `checksums.txt` | SHA-256 checksums |

## Direct install examples

```sh
# Linux (amd64)
curl -L https://github.com/goldjg/stance/releases/download/v1.0.0/stance_1.0.0_linux_amd64.tar.gz \
  | tar xz && sudo mv stance /usr/local/bin/stance

# macOS (Apple Silicon)
curl -L https://github.com/goldjg/stance/releases/download/v1.0.0/stance_1.0.0_darwin_arm64.tar.gz \
  | tar xz && sudo mv stance /usr/local/bin/stance

# macOS (Intel)
curl -L https://github.com/goldjg/stance/releases/download/v1.0.0/stance_1.0.0_darwin_amd64.tar.gz \
  | tar xz && sudo mv stance /usr/local/bin/stance
```

Windows: download `stance_<version>_windows_amd64.zip`, extract `stance.exe`,
and add it to your `PATH`.

## Checksum verification

```sh
curl -LO https://github.com/goldjg/stance/releases/download/v1.0.0/checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

## Native Linux package install notes

```sh
# Debian/Ubuntu
curl -LO https://github.com/goldjg/stance/releases/download/v1.0.0/stance_1.0.0_linux_amd64.deb
sudo dpkg -i stance_1.0.0_linux_amd64.deb

# Red Hat/Fedora
curl -LO https://github.com/goldjg/stance/releases/download/v1.0.0/stance_1.0.0_linux_amd64.rpm
sudo rpm -i stance_1.0.0_linux_amd64.rpm

# Alpine
curl -LO https://github.com/goldjg/stance/releases/download/v1.0.0/stance_1.0.0_linux_amd64.apk
sudo apk add --allow-untrusted stance_1.0.0_linux_amd64.apk
```

## Homebrew (configured for tagged releases)

Homebrew cask publishing is configured via GoReleaser to target
`goldjg/homebrew-stance` when `HOMEBREW_TAP_GITHUB_TOKEN` is configured with
write access to that repository.

```sh
brew tap goldjg/stance
brew trust goldjg/stance
brew install --cask stance
```

Uninstall:

```sh
brew uninstall --cask stance
brew untrust goldjg/stance
brew untap goldjg/stance
```

Before pushing release tags, ensure:
1. `goldjg/homebrew-stance` exists.
2. `HOMEBREW_TAP_GITHUB_TOKEN` exists in repository secrets and has write access.

## macOS signing and notarisation status

Darwin artefacts are configured to be Developer ID codesigned (hardened runtime)
when Apple signing secrets are configured in repository Actions secrets.

Notarisation is not implemented in this PR. Gatekeeper prompts may appear in
environments requiring notarised binaries. A future migration to App Store
Connect API key credentials is the expected path to enable `notarize.macos`.

### Apple signing secrets setup

Required repository secrets:

| Secret | Description |
|---|---|
| `MACOS_CERTIFICATE_P12_BASE64` | Base64-encoded Developer ID Application `.p12` |
| `MACOS_CERTIFICATE_PASSWORD` | Password used to export the `.p12` |

## WinGet status

WinGet submission is handled by the release workflow (not GoReleaser) and is
optional/token-gated.

- Package ID target: `goldjg.STANCE`
- Required secret: `WINGETCREATE_TOKEN`
- If token is not configured, WinGet publish job is skipped cleanly.

## Build from source

```sh
go install github.com/goldjg/stance/cmd/stance@latest
```

## Enterprise mirroring guidance

Release artefacts can be mirrored to internal repositories (for example,
Artifactory, Nexus, or internal package mirrors). Mirror from:

`https://github.com/goldjg/stance/releases/download/<tag>/`

and validate artefacts with `checksums.txt` as part of internal ingestion.
