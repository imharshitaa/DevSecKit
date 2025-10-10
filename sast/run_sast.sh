#!/bin/bash
TARGET_DIR=${1:-.}

echo "🔍 Running Semgrep..."
semgrep --config auto "$TARGET_DIR"

echo "🐍 Running Bandit..."
bandit -r "$TARGET_DIR"

echo "✅ SAST scan completed!"
