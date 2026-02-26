#!/usr/bin/env bash
set -u

URL=${1:-}
REPORT=${2:-reports/zap.json}

if [[ -z "$URL" ]]; then
  echo "Usage: $0 <url> [report_path]"
  exit 2
fi

mkdir -p "$(dirname "$REPORT")"

if command -v docker >/dev/null 2>&1; then
  docker run --rm -v "$(pwd)":/zap/wrk ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py -t "$URL" -J "/zap/wrk/$REPORT"
else
  echo "[ERROR] docker is required for ZAP baseline scan."
  exit 1
fi
