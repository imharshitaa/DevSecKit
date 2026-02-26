#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-}
REPORT=${2:-reports/semgrep.json}
SEMGREP_IMAGE=${SEMGREP_IMAGE:-returntocorp/semgrep:latest}
SEMGREP_EXCLUDES=${SEMGREP_EXCLUDES:-.git,node_modules,dist,build,.venv,venv,.tox,.mypy_cache}

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

echo "[INFO] SAST target: $TARGET_ABS"
echo "[INFO] Report: $REPORT_ABS"

if command -v semgrep >/dev/null 2>&1; then
  echo "[INFO] Running Semgrep via local binary"
  semgrep scan --config auto "$TARGET_ABS" \
    --exclude "$SEMGREP_EXCLUDES" \
    --metrics=off \
    --json --output "$REPORT_ABS"
elif command -v docker >/dev/null 2>&1; then
  echo "[INFO] Running Semgrep via Docker image: $SEMGREP_IMAGE"
  docker run --rm \
    -v "$TARGET_ABS:/src:ro" \
    -v "$REPORT_DIR:/out" \
    "$SEMGREP_IMAGE" semgrep scan --config auto /src \
    --exclude "$SEMGREP_EXCLUDES" \
    --metrics=off \
    --json --output "/out/$REPORT_FILE"
else
  echo "[ERROR] semgrep or docker is required."
  echo "[HINT] Install Semgrep: pipx install semgrep"
  exit 1
fi

if command -v python3 >/dev/null 2>&1; then
  COUNT=$(python3 - "$REPORT_ABS" <<'PY'
import json, sys
p = sys.argv[1]
try:
    data = json.load(open(p, encoding='utf-8'))
    print(len(data.get('results', [])))
except Exception:
    print('unknown')
PY
)
  echo "[INFO] Semgrep findings: $COUNT"
fi

echo "[OK] SAST scan finished"
