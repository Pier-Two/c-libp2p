#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
cd "${repo_root}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: check-macos-smoke.sh must run on macOS (Darwin)." >&2
  exit 1
fi

for cmd in brew cmake ctest; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "error: required command '${cmd}' is not available in PATH." >&2
    exit 1
  fi
done

for pkg in ninja bison flex openssl@3; do
  if ! brew list "${pkg}" >/dev/null 2>&1; then
    echo "error: missing Homebrew package '${pkg}'." >&2
    echo "Install it with: brew install ${pkg}" >&2
    exit 1
  fi
done

cmake --preset macos-smoke \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)" \
  -DBISON_EXECUTABLE="$(brew --prefix bison)/bin/bison" \
  -DFLEX_EXECUTABLE="$(brew --prefix flex)/bin/flex"

cmake --build --preset macos-smoke
ctest --preset macos-smoke
