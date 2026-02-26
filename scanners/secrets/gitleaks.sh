#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-}
REPORT=${2:-reports/gitleaks.json}
GITLEAKS_IMAGE=${GITLEAKS_IMAGE:-ghcr.io/gitleaks/gitleaks:latest}
GITLEAKS_REDACT=${GITLEAKS_REDACT:-90}

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

echo "[INFO] Secrets target: $TARGET_ABS"
echo "[INFO] Report: $REPORT_ABS"

if command -v gitleaks >/dev/null 2>&1; then
  echo "[INFO] Running Gitleaks via local binary"
  gitleaks detect --source "$TARGET_ABS" --report-format json --report-path "$REPORT_ABS" --exit-code 0 --redact "$GITLEAKS_REDACT"
elif command -v docker >/dev/null 2>&1; then
  echo "[INFO] Running Gitleaks via Docker image: $GITLEAKS_IMAGE"
  docker run --rm \
    -v "$TARGET_ABS:/src:ro" \
    -v "$REPORT_DIR:/report" \
    "$GITLEAKS_IMAGE" detect --source /src --report-format json --report-path "/report/$REPORT_FILE" --exit-code 0 --redact "$GITLEAKS_REDACT"
else
  echo "[ERROR] gitleaks or docker is required."
  echo "[HINT] Install Gitleaks: brew install gitleaks"
  exit 1
fi

if command -v python3 >/dev/null 2>&1; then
  COUNT=$(python3 - "$REPORT_ABS" <<'PY'
import json, sys
p = sys.argv[1]
try:
    data = json.load(open(p, encoding='utf-8'))
    print(len(data) if isinstance(data, list) else 0)
except Exception:
    print('unknown')
PY
)
  echo "[INFO] Gitleaks findings: $COUNT"
fi

echo "[OK] Secrets scan finished"
