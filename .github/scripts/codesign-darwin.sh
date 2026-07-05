#!/usr/bin/env bash
# codesign-darwin.sh — GoReleaser builds.hooks.post handler for darwin signing.
#
# Required env:
#   ARTIFACT_PATH   path to binary built by GoReleaser
#   ARTIFACT_TARGET target triple (e.g. darwin_amd64_v1, linux_arm64)
#   SIGNING_IDENTITY Developer ID Application certificate display name
#
# Behavior:
#   - signs only darwin targets
#   - skips outside darwin targets
#   - skips when codesign is unavailable (non-macOS runner)
#   - fails clearly when darwin signing prerequisites are missing

set -euo pipefail

ARTIFACT_PATH="${ARTIFACT_PATH:?ARTIFACT_PATH must be set by GoReleaser hook env}"
ARTIFACT_TARGET="${ARTIFACT_TARGET:?ARTIFACT_TARGET must be set by GoReleaser hook env}"

if [[ "$ARTIFACT_TARGET" != darwin_* ]]; then
  exit 0
fi

if ! command -v codesign > /dev/null 2>&1; then
  echo "codesign not available; skipping signing for: $ARTIFACT_PATH"
  exit 0
fi

if [[ ! -f "$ARTIFACT_PATH" ]]; then
  echo "codesign: ARTIFACT_PATH does not exist: $ARTIFACT_PATH" >&2
  exit 1
fi

if [ -z "${SIGNING_IDENTITY:-}" ]; then
  echo "codesign: SIGNING_IDENTITY is required for darwin artefact signing: $ARTIFACT_PATH" >&2
  exit 1
fi

echo "Signing: $ARTIFACT_PATH"
codesign \
  --force --verify --verbose \
  --sign "$SIGNING_IDENTITY" \
  --options runtime \
  --timestamp \
  "$ARTIFACT_PATH"

codesign --verify --deep --strict --verbose=2 "$ARTIFACT_PATH"
echo "Signed and verified: $ARTIFACT_PATH"
