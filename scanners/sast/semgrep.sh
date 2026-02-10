# scanners/sast/semgrep_scan.sh
#!/bin/bash
TARGET=$1

pip install semgrep

semgrep scan --config=auto $TARGET \
  --json > reports/semgrep.json || true

echo "[+] SAST (Semgrep) completed"
