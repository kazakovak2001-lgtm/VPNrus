#!/usr/bin/env bash
# Runs the B8B1B Python API test suite. Requires a POSIX environment with
# `fcntl` (Linux/WSL) - tokens.py's flock-based locking has no Windows
# equivalent, matching the rest of this gateway/ tree's WSL-only tooling.
#
#   bash gateway/api/tests/run_tests.sh
set -euo pipefail

GATEWAY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$GATEWAY_DIR"

PYTHON="${PYTHON:-python3}"

echo "== compileall =="
"$PYTHON" -m compileall -q api

echo
echo "== unittest discover =="
PYTHONPATH="$GATEWAY_DIR" "$PYTHON" -m unittest discover -s api/tests -t . -v
