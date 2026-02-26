#!/usr/bin/env bash
set -u

TARGET=${1:-}
OUT_DIR=${2:-reports}

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target_path> [out_dir]"
  exit 2
fi

if ! command -v dependency-check >/dev/null 2>&1; then
  echo "[ERROR] dependency-check is not installed. Install from OWASP Dependency-Check releases."
  exit 1
fi

mkdir -p "$OUT_DIR"
dependency-check --scan "$TARGET" --format JSON --out "$OUT_DIR"
