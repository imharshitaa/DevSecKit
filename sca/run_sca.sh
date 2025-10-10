#!/bin/bash
TARGET_DIR=${1:-.}

echo "🧩 Running Trivy..."
trivy fs --severity HIGH,CRITICAL --ignore-unfixed -f table "$TARGET_DIR"

echo "🕵️ Running Dependency-Check..."
docker run --rm -v "$TARGET_DIR":/src owasp/dependency-check \
  --scan /src --format "table"

echo "✅ SCA scan completed!"
