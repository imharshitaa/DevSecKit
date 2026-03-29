#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-}
OUT_DIR=${2:-reports}
DC_IMAGE=${DC_IMAGE:-owasp/dependency-check:9.0.10}
DC_NO_UPDATE=${DC_NO_UPDATE:-auto}
PROJECT_NAME=${PROJECT_NAME:-devseckit-target}
DC_DATA_DIR=${DC_DATA_DIR:-$OUT_DIR/.cache/dependency-check-data}
DC_EXCLUDES=${DC_EXCLUDES:-node_modules,dist,build,.venv,venv,.git,targets,reports}
DC_TIMEOUT_SECONDS=${DC_TIMEOUT_SECONDS:-900}

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

echo "[ERROR] Dependency-Check temporarily disabled in this project due shell compatibility issues."
echo "[HINT] Use scanners/sca/trivy.sh for SCA until dependencycheck.sh is repaired."
exit 2
