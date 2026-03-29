#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-}
REPORT=${2:-reports/gitleaks.json}
GITLEAKS_IMAGE=${GITLEAKS_IMAGE:-ghcr.io/gitleaks/gitleaks:v8.19.2}
GITLEAKS_REDACT=${GITLEAKS_REDACT:-90}
GITLEAKS_TIMEOUT_SECONDS=${GITLEAKS_TIMEOUT_SECONDS:-300}

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

TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="gtimeout"
fi

set +e
if command -v gitleaks >/dev/null 2>&1; then
  echo "[INFO] Running Gitleaks via local binary"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" "$GITLEAKS_TIMEOUT_SECONDS" gitleaks detect --source "$TARGET_ABS" --report-format json --report-path "$REPORT_ABS" --exit-code 0 --redact "$GITLEAKS_REDACT"
  else
    gitleaks detect --source "$TARGET_ABS" --report-format json --report-path "$REPORT_ABS" --exit-code 0 --redact "$GITLEAKS_REDACT"
  fi
  RC=$?
elif command -v docker >/dev/null 2>&1; then
  echo "[INFO] Running Gitleaks via Docker image: $GITLEAKS_IMAGE"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" "$GITLEAKS_TIMEOUT_SECONDS" docker run --rm \
      -v "$TARGET_ABS:/src:ro" \
      -v "$REPORT_DIR:/report" \
      "$GITLEAKS_IMAGE" detect --source /src --report-format json --report-path "/report/$REPORT_FILE" --exit-code 0 --redact "$GITLEAKS_REDACT"
  else
    docker run --rm \
      -v "$TARGET_ABS:/src:ro" \
      -v "$REPORT_DIR:/report" \
      "$GITLEAKS_IMAGE" detect --source /src --report-format json --report-path "/report/$REPORT_FILE" --exit-code 0 --redact "$GITLEAKS_REDACT"
  fi
  RC=$?
else
  echo "[ERROR] gitleaks or docker is required."
  echo "[HINT] Install Gitleaks: brew install gitleaks"
  exit 1
fi
set -e

if [[ ${RC:-1} -eq 124 ]]; then
  echo "[ERROR] Gitleaks timed out after ${GITLEAKS_TIMEOUT_SECONDS}s."
  exit 124
fi
if [[ ${RC:-1} -ne 0 ]]; then
  echo "[ERROR] Gitleaks failed (exit ${RC})."
  exit "$RC"
fi

echo "[OK] Secrets scan finished"
