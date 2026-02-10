# scanners/sca/dependency_check.sh
#!/bin/bash
TARGET=$1

sudo apt update
sudo apt install -y dependency-check

dependency-check \
  --scan $TARGET \
  --format JSON \
  --out reports/ || true

echo "[+] SCA completed"
