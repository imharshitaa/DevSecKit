#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-}
REPORT=${2:-reports/checkov.json}
CHECKOV_IMAGE=${CHECKOV_IMAGE:-bridgecrew/checkov:3.2.86}
CHECKOV_TIMEOUT_SECONDS=${CHECKOV_TIMEOUT_SECONDS:-600}

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
if command -v checkov >/dev/null 2>&1; then
  echo "[INFO] Running Checkov via local binary"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" "$CHECKOV_TIMEOUT_SECONDS" checkov -d "$TARGET_ABS" -o json --soft-fail > "$TMP_REPORT"
  else
    checkov -d "$TARGET_ABS" -o json --soft-fail > "$TMP_REPORT"
  fi
  RC=$?
elif command -v docker >/dev/null 2>&1; then
  echo "[INFO] Running Checkov via Docker image: $CHECKOV_IMAGE"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" "$CHECKOV_TIMEOUT_SECONDS" docker run --rm \
      -v "$TARGET_ABS:/src:ro" \
      -v "$REPORT_DIR:/out" \
      "$CHECKOV_IMAGE" -d /src -o json --soft-fail > "$TMP_REPORT"
  else
    docker run --rm \
      -v "$TARGET_ABS:/src:ro" \
      -v "$REPORT_DIR:/out" \
      "$CHECKOV_IMAGE" -d /src -o json --soft-fail > "$TMP_REPORT"
  fi
  RC=$?
else
  echo "[ERROR] checkov or docker is required."
  echo "[HINT] Install Checkov: pipx install checkov"
  exit 1
fi
set -e

if [[ ${RC:-1} -eq 124 ]]; then
  rm -f "$TMP_REPORT"
  echo "[ERROR] Checkov timed out after ${CHECKOV_TIMEOUT_SECONDS}s."
  exit 124
fi
if [[ ${RC:-1} -ne 0 ]]; then
  rm -f "$TMP_REPORT"
  echo "[ERROR] Checkov failed (exit ${RC})."
  exit "$RC"
fi

mv "$TMP_REPORT" "$REPORT_ABS"
echo "[OK] IaC scan finished"
