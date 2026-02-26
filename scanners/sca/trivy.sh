#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-}
REPORT=${2:-reports/trivy-sca.json}
TRIVY_IMAGE=${TRIVY_IMAGE:-aquasec/trivy:latest}
TRIVY_SKIP_DIRS=${TRIVY_SKIP_DIRS:-node_modules,dist,build,.venv,venv,.git,targets,reports}

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

echo "[INFO] SCA (Trivy) target: $TARGET_ABS"
echo "[INFO] Report: $REPORT_ABS"

IFS=',' read -r -a SKIPS <<< "$TRIVY_SKIP_DIRS"
SKIP_ARGS=()
for s in "${SKIPS[@]}"; do
  t=$(echo "$s" | xargs)
  [[ -n "$t" ]] && SKIP_ARGS+=(--skip-dirs "$TARGET_ABS/$t")
done

set +e
if command -v trivy >/dev/null 2>&1; then
  echo "[INFO] Running Trivy via local binary"
  trivy fs "$TARGET_ABS" --scanners vuln --format json --output "$REPORT_ABS" --exit-code 0 "${SKIP_ARGS[@]}"
  RC=$?
elif command -v docker >/dev/null 2>&1; then
  echo "[INFO] Running Trivy via Docker image: $TRIVY_IMAGE"
  DSKIP_ARGS=()
  for s in "${SKIPS[@]}"; do
    t=$(echo "$s" | xargs)
    [[ -n "$t" ]] && DSKIP_ARGS+=(--skip-dirs "/src/$t")
  done
  docker run --rm -v "$TARGET_ABS:/src:ro" -v "$REPORT_DIR:/out" "$TRIVY_IMAGE" \
    fs /src --scanners vuln --format json --output "/out/$REPORT_FILE" --exit-code 0 "${DSKIP_ARGS[@]}"
  RC=$?
else
  echo "[ERROR] trivy or docker is required."
  echo "[HINT] Install Trivy: brew install trivy"
  exit 1
fi
set -e

if [[ ${RC:-1} -ne 0 ]]; then
  echo "[ERROR] Trivy failed (exit ${RC})."
  exit "$RC"
fi

if [[ ! -s "$REPORT_ABS" ]]; then
  echo "[ERROR] Trivy did not produce a report."
  exit 1
fi

if command -v python3 >/dev/null 2>&1; then
  COUNT=$(python3 - "$REPORT_ABS" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding='utf-8'))
    c = 0
    for r in data.get('Results', []) or []:
        c += len(r.get('Vulnerabilities', []) or [])
    print(c)
except Exception:
    print('unknown')
PY
)
  echo "[INFO] Trivy vulnerabilities: $COUNT"
fi

echo "[OK] SCA (Trivy) scan finished"
