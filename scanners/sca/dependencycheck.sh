#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-}
OUT_DIR=${2:-reports}
DC_IMAGE=${DC_IMAGE:-owasp/dependency-check:latest}
DC_NO_UPDATE=${DC_NO_UPDATE:-auto}
PROJECT_NAME=${PROJECT_NAME:-devseckit-target}
DC_DATA_DIR=${DC_DATA_DIR:-$OUT_DIR/.cache/dependency-check-data}
DC_EXCLUDES=${DC_EXCLUDES:-node_modules,dist,build,.venv,venv,.git,targets,reports}

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target_path> [out_dir]"
  exit 2
fi

if [[ ! -d "$TARGET" ]]; then
  echo "[ERROR] Target directory not found: $TARGET"
  exit 2
fi

mkdir -p "$OUT_DIR"
mkdir -p "$DC_DATA_DIR"
TARGET_ABS=$(cd "$TARGET" && pwd -P)
OUT_ABS=$(cd "$OUT_DIR" && pwd -P)
DATA_ABS=$(cd "$DC_DATA_DIR" && pwd -P)

echo "[INFO] SCA target: $TARGET_ABS"
echo "[INFO] Output directory: $OUT_ABS"
echo "[INFO] Dependency-Check data dir: $DATA_ABS"

IFS=',' read -r -a EXCLUDE_LIST <<< "$DC_EXCLUDES"
EXCLUDE_ARGS=()
for ex in "${EXCLUDE_LIST[@]}"; do
  ex_trimmed=$(echo "$ex" | xargs)
  if [[ -n "$ex_trimmed" ]]; then
    EXCLUDE_ARGS+=(--exclude "$TARGET_ABS/$ex_trimmed/**")
  fi
done

HAS_DB_CACHE=false
if compgen -G "$DATA_ABS/*" >/dev/null; then
  HAS_DB_CACHE=true
fi

USE_NO_UPDATE=false
case "$DC_NO_UPDATE" in
  true) USE_NO_UPDATE=true ;;
  false) USE_NO_UPDATE=false ;;
  auto)
    if [[ "$HAS_DB_CACHE" == "true" ]]; then
      USE_NO_UPDATE=true
    else
      USE_NO_UPDATE=false
    fi
    ;;
  *)
    echo "[WARN] Invalid DC_NO_UPDATE='$DC_NO_UPDATE'. Using auto."
    if [[ "$HAS_DB_CACHE" == "true" ]]; then
      USE_NO_UPDATE=true
    fi
    ;;
esac

DC_ARGS=(--scan "$TARGET_ABS" --format JSON --out "$OUT_ABS" --project "$PROJECT_NAME" --data "$DATA_ABS")
DC_ARGS+=("${EXCLUDE_ARGS[@]}")
if [[ "$USE_NO_UPDATE" == "true" ]]; then
  DC_ARGS+=(--noupdate)
fi

if command -v dependency-check >/dev/null 2>&1; then
  echo "[INFO] Running Dependency-Check via local binary"
  set +e
  dependency-check "${DC_ARGS[@]}"
  SCAN_RC=$?
  set -e
elif command -v docker >/dev/null 2>&1; then
  echo "[INFO] Running Dependency-Check via Docker image: $DC_IMAGE"
  DOCKER_ARGS=(--scan /src --format JSON --out /report --project "$PROJECT_NAME" --data /usr/share/dependency-check/data)
  for ex in "${EXCLUDE_LIST[@]}"; do
    ex_trimmed=$(echo "$ex" | xargs)
    if [[ -n "$ex_trimmed" ]]; then
      DOCKER_ARGS+=(--exclude "/src/$ex_trimmed/**")
    fi
  done
  if [[ "$USE_NO_UPDATE" == "true" ]]; then
    DOCKER_ARGS+=(--noupdate)
  fi
  set +e
  docker run --rm \
    -v "$TARGET_ABS:/src:ro" \
    -v "$OUT_ABS:/report" \
    -v "$DATA_ABS:/usr/share/dependency-check/data" \
    "$DC_IMAGE" "${DOCKER_ARGS[@]}"
  SCAN_RC=$?
  set -e
else
  echo "[ERROR] dependency-check or docker is required."
  echo "[HINT] Install Dependency-Check: brew install dependency-check"
  exit 1
fi

LATEST_REPORT=$(ls -t "$OUT_ABS"/dependency-check-report*.json 2>/dev/null | head -n 1 || true)
if [[ ${SCAN_RC:-1} -ne 0 && -n "$LATEST_REPORT" && -s "$LATEST_REPORT" ]]; then
  echo "[WARN] Dependency-Check exited with code ${SCAN_RC}, but a report was generated."
  echo "[WARN] Continuing so findings can still be parsed."
  SCAN_RC=0
fi

if [[ ${SCAN_RC:-1} -ne 0 ]]; then
  echo "[ERROR] Dependency-Check failed (exit ${SCAN_RC})."
  if [[ "$USE_NO_UPDATE" == "true" && "$HAS_DB_CACHE" != "true" ]]; then
    echo "[HINT] No local DB cache found. Re-run with DC_NO_UPDATE=false for initial DB download."
  fi
  if [[ "$USE_NO_UPDATE" == "false" ]]; then
    echo "[HINT] Initial DB update can take time. Later runs will be faster with cached data."
  fi
  exit "$SCAN_RC"
fi

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
