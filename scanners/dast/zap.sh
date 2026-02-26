#!/usr/bin/env bash
set -euo pipefail

URL=${1:-}
REPORT=${2:-reports/zap.json}
ZAP_IMAGE=${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}

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
REPORT_ABS="$REPORT_DIR/$REPORT_FILE"

echo "[INFO] DAST target URL: $URL"
echo "[INFO] Report: $REPORT_ABS"

if command -v docker >/dev/null 2>&1; then
  echo "[INFO] Running ZAP Baseline via Docker image: $ZAP_IMAGE"
  docker run --rm \
    -v "$REPORT_DIR:/zap/wrk" \
    "$ZAP_IMAGE" zap-baseline.py \
      -t "$URL" \
      -J "/zap/wrk/$REPORT_FILE" \
      -I
else
  echo "[ERROR] docker is required for ZAP baseline scan."
  echo "[HINT] Install/start Docker Desktop and verify with: docker ps"
  exit 1
fi

echo "[OK] DAST scan finished"
