# scanners/dast/zap_scan.sh
#!/bin/bash
URL=$1

docker run --rm \
  -v $(pwd):/zap/wrk \
  owasp/zap2docker-stable zap-baseline.py \
  -t $URL \
  -J reports/zap.json || true

echo "[+] DAST completed"
