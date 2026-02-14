#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
cd "${repo_root}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "error: check-linux-smoke.sh must run on Linux." >&2
  exit 1
fi

for cmd in cmake ctest clang-format cppcheck git; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "error: required command '${cmd}' is not available in PATH." >&2
    exit 1
  fi
done

cmake --preset linux-smoke
cmake --build --preset linux-smoke
ctest --preset linux-smoke

if [ -n "${GITHUB_BASE_REF:-}" ]; then
  git fetch --no-tags origin "${GITHUB_BASE_REF}" || true
  range="origin/${GITHUB_BASE_REF}...HEAD"
elif [ -n "${FAST_LANE_DIFF_RANGE:-}" ]; then
  range="${FAST_LANE_DIFF_RANGE}"
elif upstream_ref="$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null)"; then
  range="${upstream_ref}...HEAD"
elif git show-ref --verify --quiet refs/remotes/origin/main; then
  range="origin/main...HEAD"
elif git rev-parse --verify HEAD~1 >/dev/null 2>&1; then
  range="$(git rev-parse HEAD~1)...HEAD"
else
  echo "No diff range available; skipping format check."
  range=""
fi

if [ -n "${range}" ]; then
  files="$(git diff --name-only "${range}" -- '*.c' '*.h' | grep -E '^(src|include|tests)/' || true)"
  if [ -z "${files}" ]; then
    echo "No changed C source/header files in src/include/tests; skipping format check."
  else
    echo "Formatting check scope:"
    echo "${files}"
    echo "${files}" | xargs clang-format --style=file --dry-run --Werror
  fi
fi

cppcheck \
  --error-exitcode=1 \
  --std=c99 \
  --enable=warning,portability \
  --quiet \
  --suppress=missingIncludeSystem \
  src/multiformats \
  include/multiformats \
  tests/multiformats \
  src/peer_id \
  include/peer_id \
  tests/peer_id
