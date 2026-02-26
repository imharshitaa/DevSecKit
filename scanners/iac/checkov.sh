#!/usr/bin/env bash
set -u

TARGET=${1:-}
REPORT=${2:-reports/checkov.json}

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target_path> [report_path]"
  exit 2
fi

if ! command -v checkov >/dev/null 2>&1; then
  echo "[ERROR] checkov is not installed. Install: pipx install checkov"
  exit 1
fi

mkdir -p "$(dirname "$REPORT")"
checkov -d "$TARGET" -o json > "$REPORT"
