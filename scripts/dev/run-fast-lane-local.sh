#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
cd "${repo_root}"

platform="auto"

usage() {
  cat <<'EOF'
Usage: scripts/dev/run-fast-lane-local.sh [--platform auto|macos|linux] [--diff-range <git-range>]

Runs local smoke checks that mirror the macOS/Linux ci-fast workflow.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)
      platform="${2:-}"
      shift 2
      ;;
    --diff-range)
      export FAST_LANE_DIFF_RANGE="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument '$1'" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "${platform}" == "auto" ]]; then
  case "$(uname -s)" in
    Darwin) platform="macos" ;;
    Linux) platform="linux" ;;
    *)
      echo "error: unsupported host platform '$(uname -s)'. Use --platform explicitly." >&2
      exit 1
      ;;
  esac
fi

case "${platform}" in
  macos)
    echo "Running local fast-lane checks: macOS smoke"
    "${repo_root}/scripts/ci/check-macos-smoke.sh"
    ;;
  linux)
    echo "Running local fast-lane checks: Linux smoke"
    "${repo_root}/scripts/ci/check-linux-smoke.sh"
    ;;
  *)
    echo "error: invalid --platform value '${platform}' (expected auto|macos|linux)." >&2
    exit 1
    ;;
esac
