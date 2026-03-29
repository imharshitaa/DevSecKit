#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-}
REPORT=${2:-reports/semgrep.json}
SEMGREP_IMAGE=${SEMGREP_IMAGE:-returntocorp/semgrep:1.74.0}
SEMGREP_EXCLUDES=${SEMGREP_EXCLUDES:-.git,node_modules,dist,build,.venv,venv,.tox,.mypy_cache}
SEMGREP_TIMEOUT_SECONDS=${SEMGREP_TIMEOUT_SECONDS:-600}

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

echo "[INFO] SAST target: $TARGET_ABS"
echo "[INFO] Report: $REPORT_ABS"
echo "[INFO] Timeout seconds: $SEMGREP_TIMEOUT_SECONDS"

if command -v semgrep >/dev/null 2>&1; then
  echo "[INFO] Running Semgrep via local binary"
  set +e
  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" "$SEMGREP_TIMEOUT_SECONDS" semgrep scan --config auto "$TARGET_ABS" \
      --exclude "$SEMGREP_EXCLUDES" \
      --json --output "$REPORT_ABS"
  else
    semgrep scan --config auto "$TARGET_ABS" \
      --exclude "$SEMGREP_EXCLUDES" \
      --json --output "$REPORT_ABS"
  fi
  RC=$?
  set -e
elif command -v docker >/dev/null 2>&1; then
  echo "[INFO] Running Semgrep via Docker image: $SEMGREP_IMAGE"
  set +e
  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" "$SEMGREP_TIMEOUT_SECONDS" docker run --rm \
      -v "$TARGET_ABS:/src:ro" \
      -v "$REPORT_DIR:/out" \
      "$SEMGREP_IMAGE" semgrep scan --config auto /src \
      --exclude "$SEMGREP_EXCLUDES" \
      --json --output "/out/$REPORT_FILE"
  else
    docker run --rm \
      -v "$TARGET_ABS:/src:ro" \
      -v "$REPORT_DIR:/out" \
      "$SEMGREP_IMAGE" semgrep scan --config auto /src \
      --exclude "$SEMGREP_EXCLUDES" \
      --json --output "/out/$REPORT_FILE"
  fi
  RC=$?
  set -e
else
  echo "[ERROR] semgrep or docker is required."
  echo "[HINT] Install Semgrep: pipx install semgrep"
  exit 1
fi

if [[ ${RC:-1} -eq 124 ]]; then
  echo "[ERROR] Semgrep timed out after ${SEMGREP_TIMEOUT_SECONDS}s."
  exit 124
fi
if [[ ${RC:-1} -ne 0 ]]; then
  echo "[ERROR] Semgrep failed (exit ${RC})."
  exit "$RC"
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
