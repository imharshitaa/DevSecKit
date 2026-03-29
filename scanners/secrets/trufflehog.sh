#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-}
REPORT=${2:-reports/trufflehog.json}
TRUFFLEHOG_IMAGE=${TRUFFLEHOG_IMAGE:-trufflesecurity/trufflehog:3.83.0}
TRUFFLEHOG_TIMEOUT_SECONDS=${TRUFFLEHOG_TIMEOUT_SECONDS:-360}

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target_path> [report_path]"
  exit 2
fi

if [[ ! -d "$TARGET" ]]; then
  echo "[ERROR] Target directory not found: $TARGET"
  exit 2
fi

mkdir -p "$(dirname "$REPORT")"
TARGET_ABS=$(cd "$TARGET" && pwd -P)
REPORT_DIR=$(cd "$(dirname "$REPORT")" && pwd -P)
REPORT_FILE=$(basename "$REPORT")
REPORT_ABS="$REPORT_DIR/$REPORT_FILE"
TMP_REPORT="$REPORT_ABS.tmp"

TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="gtimeout"
fi

set +e
if command -v trufflehog >/dev/null 2>&1; then
  echo "[INFO] Running TruffleHog via local binary"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" "$TRUFFLEHOG_TIMEOUT_SECONDS" trufflehog filesystem "$TARGET_ABS" --json > "$TMP_REPORT"
  else
    trufflehog filesystem "$TARGET_ABS" --json > "$TMP_REPORT"
  fi
  RC=$?
elif command -v docker >/dev/null 2>&1; then
  echo "[INFO] Running TruffleHog via Docker image: $TRUFFLEHOG_IMAGE"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" "$TRUFFLEHOG_TIMEOUT_SECONDS" docker run --rm -v "$TARGET_ABS:/src:ro" "$TRUFFLEHOG_IMAGE" filesystem /src --json > "$TMP_REPORT"
  else
    docker run --rm -v "$TARGET_ABS:/src:ro" "$TRUFFLEHOG_IMAGE" filesystem /src --json > "$TMP_REPORT"
  fi
  RC=$?
else
  echo "[ERROR] trufflehog or docker is required."
  exit 1
fi
set -e

if [[ ${RC:-1} -eq 124 ]]; then
  rm -f "$TMP_REPORT"
  echo "[ERROR] TruffleHog timed out after ${TRUFFLEHOG_TIMEOUT_SECONDS}s."
  exit 124
fi

if [[ ${RC:-1} -ne 0 && ! -s "$TMP_REPORT" ]]; then
  rm -f "$TMP_REPORT"
  echo "[ERROR] TruffleHog failed (exit ${RC})."
  exit "$RC"
fi

mv "$TMP_REPORT" "$REPORT_ABS"
echo "[OK] Secrets (TruffleHog) scan finished"
