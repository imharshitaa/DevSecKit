# scanners/secrets/gitleaks_scan.sh
#!/bin/bash
TARGET=$1

curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/install.sh | sh

gitleaks detect \
  --source $TARGET \
  --report-format json \
  --report-path reports/gitleaks.json \
  --no-git || true

echo "[+] Secrets scan completed"
