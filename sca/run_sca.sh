#!/bin/bash
TARGET_DIR=${1:-.}

echo "🧩 Running Safety..."
# Make sure requirements.txt exists in target
if [ -f "$TARGET_DIR/requirements.txt" ]; then
    pip install safety
    safety check -r "$TARGET_DIR/requirements.txt"
else
    echo "⚠️ No requirements.txt found in $TARGET_DIR"
fi

echo "🕵️ Running pip-audit..."
pip install pip-audit
cd "$TARGET_DIR" || exit
pip-audit

echo "✅ SCA scan completed!"
