#!/usr/bin/env bash
# Runs the B8B1C1 operator-CLI test suite. Requires a POSIX environment
# with `fcntl` (Linux/WSL) - matching gateway/api/tests/run_tests.sh.
#
#   bash gateway/tools/tests/run_tests.sh
set -euo pipefail

GATEWAY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$GATEWAY_DIR"

PYTHON="${PYTHON:-python3}"

echo "== compileall =="
"$PYTHON" -m compileall -q tools

echo
echo "== unittest discover =="
PYTHONPATH="$GATEWAY_DIR" "$PYTHON" -m unittest discover -s tools/tests -t . -v
