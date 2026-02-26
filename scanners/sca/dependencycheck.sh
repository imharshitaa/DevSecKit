#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-}
OUT_DIR=${2:-reports}
DC_IMAGE=${DC_IMAGE:-owasp/dependency-check:latest}
DC_NO_UPDATE=${DC_NO_UPDATE:-true}
PROJECT_NAME=${PROJECT_NAME:-devseckit-target}

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target_path> [out_dir]"
  exit 2
fi

if [[ ! -d "$TARGET" ]]; then
  echo "[ERROR] Target directory not found: $TARGET"
  exit 2
fi

mkdir -p "$OUT_DIR"
TARGET_ABS=$(cd "$TARGET" && pwd -P)
OUT_ABS=$(cd "$OUT_DIR" && pwd -P)

echo "[INFO] SCA target: $TARGET_ABS"
echo "[INFO] Output directory: $OUT_ABS"

DC_ARGS=(--scan "$TARGET_ABS" --format JSON --out "$OUT_ABS" --project "$PROJECT_NAME")
if [[ "$DC_NO_UPDATE" == "true" ]]; then
  DC_ARGS+=(--noupdate)
fi

if command -v dependency-check >/dev/null 2>&1; then
  echo "[INFO] Running Dependency-Check via local binary"
  dependency-check "${DC_ARGS[@]}"
elif command -v docker >/dev/null 2>&1; then
  echo "[INFO] Running Dependency-Check via Docker image: $DC_IMAGE"
  DOCKER_ARGS=(--scan /src --format JSON --out /report --project "$PROJECT_NAME")
  if [[ "$DC_NO_UPDATE" == "true" ]]; then
    DOCKER_ARGS+=(--noupdate)
  fi
  docker run --rm \
    -v "$TARGET_ABS:/src:ro" \
    -v "$OUT_ABS:/report" \
    "$DC_IMAGE" "${DOCKER_ARGS[@]}"
else
  echo "[ERROR] dependency-check or docker is required."
  echo "[HINT] Install Dependency-Check: brew install dependency-check"
  exit 1
fi

LATEST_REPORT=$(ls -t "$OUT_ABS"/dependency-check-report*.json 2>/dev/null | head -n 1 || true)
if [[ -n "$LATEST_REPORT" && -f "$LATEST_REPORT" && $(command -v python3 >/dev/null 2>&1; echo $?) -eq 0 ]]; then
  COUNT=$(python3 - "$LATEST_REPORT" <<'PY'
import json, sys
p = sys.argv[1]
try:
    data = json.load(open(p, encoding='utf-8'))
    c = 0
    for d in data.get('dependencies', []):
        c += len(d.get('vulnerabilities', []) or [])
    print(c)
except Exception:
    print('unknown')
PY
)
  echo "[INFO] Dependency-Check vulnerabilities: $COUNT"
fi

echo "[OK] SCA scan finished"
