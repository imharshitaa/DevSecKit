#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-}
REPORT=${2:-reports/trufflehog.json}
TRUFFLEHOG_IMAGE=${TRUFFLEHOG_IMAGE:-trufflesecurity/trufflehog:latest}

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

echo "[INFO] Secrets (TruffleHog) target: $TARGET_ABS"
echo "[INFO] Report: $REPORT_ABS"

set +e
if command -v trufflehog >/dev/null 2>&1; then
  echo "[INFO] Running TruffleHog via local binary"
  trufflehog filesystem "$TARGET_ABS" --json > "$TMP_REPORT"
  RC=$?
elif command -v docker >/dev/null 2>&1; then
  echo "[INFO] Running TruffleHog via Docker image: $TRUFFLEHOG_IMAGE"
  docker run --rm -v "$TARGET_ABS:/src:ro" "$TRUFFLEHOG_IMAGE" filesystem /src --json > "$TMP_REPORT"
  RC=$?
else
  echo "[ERROR] trufflehog or docker is required."
  echo "[HINT] Install TruffleHog: brew install trufflehog"
  exit 1
fi
set -e

# TruffleHog may return non-zero when findings are detected; treat as success if output exists.
if [[ ${RC:-1} -ne 0 && ! -s "$TMP_REPORT" ]]; then
  rm -f "$TMP_REPORT"
  echo "[ERROR] TruffleHog failed (exit ${RC})."
  exit "$RC"
fi

mv "$TMP_REPORT" "$REPORT_ABS"

if command -v python3 >/dev/null 2>&1; then
  COUNT=$(python3 - "$REPORT_ABS" <<'PY'
import sys
c = 0
with open(sys.argv[1], encoding='utf-8', errors='ignore') as f:
    for line in f:
        if line.strip():
            c += 1
print(c)
PY
)
  echo "[INFO] TruffleHog findings (raw entries): $COUNT"
fi

echo "[OK] Secrets (TruffleHog) scan finished"
