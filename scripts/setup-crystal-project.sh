#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAINS="$ROOT/.toolchains"

CRYSTAL_121_ARCHIVE="${CRYSTAL_121_ARCHIVE:-/mnt/data/crystal-1.21.1-1-linux-x86_64-bundled-llvm23.1.2.tar.gz}"
SHARDS_ARCHIVE="${SHARDS_ARCHIVE:-/mnt/data/crystal-1.21.0-1-linux-x86_64-bundled.tar.gz}"
CRYSTAL_118_ARCHIVE="${CRYSTAL_118_ARCHIVE:-/mnt/data/crystal-1.18.0-1-linux-x86_64-bundled.tar.gz}"

require_archive() {
  local archive=$1
  if [[ ! -f "$archive" ]]; then
    printf 'required toolchain archive not found: %s\n' "$archive" >&2
    exit 1
  fi
}

extract_toolchain() {
  local archive=$1
  local dir=$2
  local marker="$TOOLCHAINS/$dir/bin/crystal"

  if [[ ! -x "$marker" ]]; then
    rm -rf "$TOOLCHAINS/$dir"
    tar -xzf "$archive" -C "$TOOLCHAINS"
  fi
}

command -v tar >/dev/null 2>&1 || {
  echo 'tar is required to extract the bundled Crystal toolchains' >&2
  exit 1
}

require_archive "$CRYSTAL_121_ARCHIVE"
require_archive "$SHARDS_ARCHIVE"
require_archive "$CRYSTAL_118_ARCHIVE"
mkdir -p "$TOOLCHAINS"

extract_toolchain "$CRYSTAL_121_ARCHIVE" crystal-1.21.1-1
extract_toolchain "$SHARDS_ARCHIVE" crystal-1.21.0-1
extract_toolchain "$CRYSTAL_118_ARCHIVE" crystal-1.18.0-1

mkdir -p "$ROOT/bin"
ln -sfn "$TOOLCHAINS/crystal-1.21.1-1/bin/crystal" "$ROOT/bin/crystal"
ln -sfn "$TOOLCHAINS/crystal-1.21.1-1/bin/crystal" "$ROOT/bin/crystal-1.21"
ln -sfn "$TOOLCHAINS/crystal-1.18.0-1/bin/crystal" "$ROOT/bin/crystal-1.18"
ln -sfn "$TOOLCHAINS/crystal-1.21.0-1/bin/shards" "$ROOT/bin/shards"

cat > "$ROOT/env.sh" <<EOF_ENV
export ACL_RESEARCH_ROOT="$ROOT"
export PATH="$ROOT/bin:\$PATH"
export CRYSTAL_CACHE_DIR="$ROOT/.cache/crystal"
EOF_ENV
mkdir -p "$ROOT/.cache/crystal"

"$ROOT/bin/crystal" --version
"$ROOT/bin/shards" --version
printf 'Compatibility compiler: '
"$ROOT/bin/crystal-1.18" --version | head -1
