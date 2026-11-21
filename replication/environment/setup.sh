#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

python3 --version
python3 -m pip install --upgrade pip
python3 -m pip install -r "$SCRIPT_DIR/requirements.txt"
if [ -f "$ROOT/requirements.txt" ]; then
  python3 -m pip install -r "$ROOT/requirements.txt"
fi
