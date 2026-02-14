#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
cd "${repo_root}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: not inside a git worktree." >&2
  exit 1
fi

git config core.hooksPath .githooks
chmod +x .githooks/pre-push
chmod +x scripts/dev/run-fast-lane-local.sh
chmod +x scripts/ci/check-macos-smoke.sh
chmod +x scripts/ci/check-linux-smoke.sh

echo "Installed git hook path: .githooks"
echo "pre-push now runs local fast-lane checks."
echo "Set LIBP2P_SKIP_FAST_HOOK=1 to bypass once."
