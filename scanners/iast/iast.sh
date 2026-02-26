#!/usr/bin/env bash
set -euo pipefail

URL=${1:-}
REPORT=${2:-reports/iast-lite.json}

if [[ -z "$URL" ]]; then
  echo "Usage: $0 <url> [report_path]"
  exit 2
fi

if [[ ! "$URL" =~ ^https?:// ]]; then
  echo "[ERROR] URL must start with http:// or https://"
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 is required for IAST-lite checks."
  exit 1
fi

mkdir -p "$(dirname "$REPORT")"

python3 - "$URL" "$REPORT" <<'PY'
import json
import ssl
import sys
import urllib.request
from http.cookies import SimpleCookie

url = sys.argv[1]
report_path = sys.argv[2]

required_headers = {
    "strict-transport-security": ("HIGH", "Missing HSTS header"),
    "content-security-policy": ("HIGH", "Missing CSP header"),
    "x-frame-options": ("MEDIUM", "Missing X-Frame-Options header"),
    "x-content-type-options": ("MEDIUM", "Missing X-Content-Type-Options header"),
    "referrer-policy": ("LOW", "Missing Referrer-Policy header"),
}

result = {
    "url": url,
    "timestamp_utc": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    "status_code": None,
    "headers": {},
    "findings": [],
}

ctx = ssl.create_default_context()
try:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        result["status_code"] = getattr(resp, "status", None)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        result["headers"] = headers
except Exception as exc:
    result["error"] = str(exc)
else:
    for key, (severity, title) in required_headers.items():
        if key not in headers:
            result["findings"].append(
                {
                    "severity": severity,
                    "title": title,
                    "evidence": f"Header '{key}' was not returned by {url}",
                    "recommendation": f"Configure '{key}' at reverse proxy/app gateway.",
                }
            )

    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        cookie = SimpleCookie()
        try:
            cookie.load(set_cookie)
        except Exception:
            cookie = None
        if cookie:
            for name, morsel in cookie.items():
                attrs = {k.lower() for k in morsel.keys() if morsel[k]}
                if "secure" not in attrs:
                    result["findings"].append(
                        {
                            "severity": "HIGH",
                            "title": f"Cookie '{name}' missing Secure flag",
                            "evidence": f"Set-Cookie for '{name}' does not include Secure",
                            "recommendation": "Set Secure on session/auth cookies.",
                        }
                    )
                if "httponly" not in attrs:
                    result["findings"].append(
                        {
                            "severity": "MEDIUM",
                            "title": f"Cookie '{name}' missing HttpOnly flag",
                            "evidence": f"Set-Cookie for '{name}' does not include HttpOnly",
                            "recommendation": "Set HttpOnly on session/auth cookies.",
                        }
                    )

    if url.startswith("http://"):
        result["findings"].append(
            {
                "severity": "MEDIUM",
                "title": "Insecure transport scheme (HTTP)",
                "evidence": f"Target URL uses HTTP: {url}",
                "recommendation": "Use HTTPS in all environments that handle sensitive traffic.",
            }
        )

with open(report_path, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

print(f"[INFO] IAST-lite findings: {len(result.get('findings', []))}")
if result.get("error"):
    print(f"[WARN] Runtime check failed: {result['error']}")
PY

echo "[OK] IAST-lite scan finished"
