#!/usr/bin/env bash
set -u

TARGET=${1:-}
REPORT=${2:-reports/semgrep.json}

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target_path> [report_path]"
  exit 2
fi

if ! command -v semgrep >/dev/null 2>&1; then
  echo "[ERROR] semgrep is not installed. Install: pipx install semgrep or pip install semgrep"
  exit 1
fi

mkdir -p "$(dirname "$REPORT")"
semgrep scan --config=auto "$TARGET" --json --output "$REPORT"
