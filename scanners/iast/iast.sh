#!/usr/bin/env bash
set -u

URL=${1:-}
REPORT=${2:-reports/iast-lite.json}

if [[ -z "$URL" ]]; then
  echo "Usage: $0 <url> [report_path]"
  exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "[ERROR] curl is required for IAST-lite checks."
  exit 1
fi

mkdir -p "$(dirname "$REPORT")"

python3 - "$URL" "$REPORT" <<'PY'
import json
import sys
import urllib.request

url = sys.argv[1]
report_path = sys.argv[2]

checks = {
    "strict-transport-security": "Missing HSTS header",
    "content-security-policy": "Missing CSP header",
    "x-frame-options": "Missing X-Frame-Options header",
    "x-content-type-options": "Missing X-Content-Type-Options header",
    "referrer-policy": "Missing Referrer-Policy header",
}

result = {"url": url, "findings": []}

try:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
except Exception as exc:
    result["error"] = str(exc)
else:
    for key, message in checks.items():
        if key not in headers:
            result["findings"].append(
                {
                    "severity": "MEDIUM",
                    "title": message,
                    "evidence": f"Header '{key}' not returned by {url}",
                }
            )

with open(report_path, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)
PY
