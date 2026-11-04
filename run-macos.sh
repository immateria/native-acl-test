#!/usr/bin/env bash
# Invoke with: bash ./run-macos.sh --profile full
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(uname -s)" != Darwin ]]; then
  echo 'This launcher requires native macOS; use python3 run.py --model-only for portable checks.' >&2
  exit 2
fi
PYTHON_BIN="${PYTHON:-python3}"
"$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 2)' || {
  echo 'Python 3.9+ is required. Set PYTHON to its executable path.' >&2
  exit 2
}
exec "$PYTHON_BIN" "$ROOT/run.py" "$@"
