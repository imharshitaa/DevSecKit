#!/usr/bin/env bash
set -euo pipefail

URL=${1:-}
REPORT=${2:-reports/zap.json}
ZAP_IMAGE=${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:2.14.0}
ZAP_TIMEOUT_SECONDS=${ZAP_TIMEOUT_SECONDS:-1200}

if [[ -z "$URL" ]]; then
  echo "Usage: $0 <url> [report_path]"
  exit 2
fi

if [[ ! "$URL" =~ ^https?:// ]]; then
  echo "[ERROR] URL must start with http:// or https://"
  exit 2
fi

mkdir -p "$(dirname "$REPORT")"
REPORT_DIR=$(cd "$(dirname "$REPORT")" && pwd -P)
REPORT_FILE=$(basename "$REPORT")

TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="gtimeout"
fi

if command -v docker >/dev/null 2>&1; then
  echo "[INFO] Running ZAP Baseline via Docker image: $ZAP_IMAGE"
  set +e
  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" "$ZAP_TIMEOUT_SECONDS" docker run --rm \
      -v "$REPORT_DIR:/zap/wrk" \
      "$ZAP_IMAGE" zap-baseline.py -t "$URL" -J "/zap/wrk/$REPORT_FILE" -I
  else
    docker run --rm \
      -v "$REPORT_DIR:/zap/wrk" \
      "$ZAP_IMAGE" zap-baseline.py -t "$URL" -J "/zap/wrk/$REPORT_FILE" -I
  fi
  RC=$?
  set -e
else
  echo "[ERROR] docker is required for ZAP baseline scan."
  exit 1
fi

if [[ ${RC:-1} -eq 124 ]]; then
  echo "[ERROR] ZAP timed out after ${ZAP_TIMEOUT_SECONDS}s."
  exit 124
fi
if [[ ${RC:-1} -ne 0 ]]; then
  echo "[ERROR] ZAP failed (exit ${RC})."
  exit "$RC"
fi

echo "[OK] DAST scan finished"
