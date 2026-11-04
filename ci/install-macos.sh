#!/usr/bin/env bash
set -euo pipefail
[[ $(uname -s) == 'Darwin' ]]
case $(uname -m) in
  arm64|x86_64) ;;
  *) printf 'unsupported macOS architecture: %s\n' "$(uname -m)" >&2; exit 1 ;;
esac
version=1.21.1
url="https://github.com/crystal-lang/crystal/releases/download/$version/crystal-$version-1-darwin-universal.tar.gz"
dir=$(mktemp -d "$RUNNER_TEMP/acl-crystal.XXXXXX")
cd "$dir"
curl --fail --location --silent --show-error --retry 3 -o crystal.tar.gz "$url"
printf '%s  crystal.tar.gz\n' ba34fa7fb8bc8b951f12d17e12f69c9d7ccce38900caa4b8a17f1b4f29d37605 | shasum -a 256 -c -
tar -xzf crystal.tar.gz
bin="$dir/crystal-$version-1/bin"
"$bin/crystal" --version
printf '%s\n' "$bin" >> "$GITHUB_PATH"
