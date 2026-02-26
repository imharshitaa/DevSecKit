#!/usr/bin/env bash
set -u

TARGET=${1:-}
REPORT=${2:-reports/gitleaks.json}

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target_path> [report_path]"
  exit 2
fi

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "[ERROR] gitleaks is not installed. Install: https://github.com/gitleaks/gitleaks"
  exit 1
fi

mkdir -p "$(dirname "$REPORT")"
gitleaks detect --source "$TARGET" --no-git --report-format json --report-path "$REPORT"
