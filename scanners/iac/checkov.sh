#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-}
REPORT=${2:-reports/checkov.json}
CHECKOV_IMAGE=${CHECKOV_IMAGE:-bridgecrew/checkov:latest}

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

echo "[INFO] IaC target: $TARGET_ABS"
echo "[INFO] Report: $REPORT_ABS"

if command -v checkov >/dev/null 2>&1; then
  echo "[INFO] Running Checkov via local binary"
  checkov -d "$TARGET_ABS" -o json --soft-fail > "$TMP_REPORT"
elif command -v docker >/dev/null 2>&1; then
  echo "[INFO] Running Checkov via Docker image: $CHECKOV_IMAGE"
  docker run --rm \
    -v "$TARGET_ABS:/src:ro" \
    -v "$REPORT_DIR:/out" \
    "$CHECKOV_IMAGE" -d /src -o json --soft-fail > "$TMP_REPORT"
else
  echo "[ERROR] checkov or docker is required."
  echo "[HINT] Install Checkov: pipx install checkov"
  exit 1
fi

if [[ ! -s "$TMP_REPORT" ]]; then
  rm -f "$TMP_REPORT"
  echo "[ERROR] Checkov did not produce a valid report."
  exit 1
fi

mv "$TMP_REPORT" "$REPORT_ABS"

if command -v python3 >/dev/null 2>&1; then
  COUNT=$(python3 - "$REPORT_ABS" <<'PY'
import json, sys
p = sys.argv[1]
try:
    data = json.load(open(p, encoding='utf-8'))
    print(len(data.get('results', {}).get('failed_checks', [])))
except Exception:
    print('unknown')
PY
)
  echo "[INFO] Checkov failed checks: $COUNT"
fi

echo "[OK] IaC scan finished"
