#!/usr/bin/env bash
# Run on macOS with its SDK and an installed Crystal >= 1.18; not Linux bootstrap.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$(uname -s)" == Darwin ]] || { echo 'This gate requires native macOS.' >&2; exit 1; }
mkdir -p "$ROOT/build"
crystal --version
shards --version
cc -std=c11 -Wall -Wextra -Werror "$ROOT/scripts/probes/darwin_acl_abi.c" -o "$ROOT/build/darwin-acl-abi"
"$ROOT/build/darwin-acl-abi"
cd "$ROOT/acl"
shards check
crystal tool format --check src spec examples
crystal spec --error-trace --error-on-warnings
crystal build spec/compile/darwin_api.cr --error-on-warnings -o "$ROOT/build/darwin-api"
