#!/usr/bin/env bash
# Run transport interop tests for c-libp2p against other libp2p implementations.
# Defaults to every other implementation but can be limited via --against/--quick.

set -euo pipefail

C_IMPL_ID="${C_IMPL_ID:-c-v0.0.1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INTEROP_DIR="${REPO_ROOT}/tools/test-plans/transport-interop-v2"
RUNNER="${INTEROP_DIR}/run_tests.sh"

usage() {
    cat <<'USAGE'
Run c-libp2p transport interoperability tests.

Usage: run_transport_interop.sh [options]

Options:
  --against LIST    Comma-separated substrings to limit the peer implementations
                    (e.g. "rust" or "rust-v0.56,go-v0.44"). Defaults to all.
  --quick           Shortcut for "--against rust" to keep the run short.
  --workers N       Pass through to run_tests.sh --workers.
  --cache-dir DIR   Pass through to run_tests.sh --cache-dir.
  --debug           Enable debug mode inside the test containers.
  --force-rebuild   Force Docker image rebuilds for the selected implementations.
  --snapshot        Request a snapshot after the run.
  --yes, -y         Skip the confirmation prompt inside run_tests.sh.
  --check-deps      Only verify dependencies and exit.
  --help, -h        Show this help message.
USAGE
}

AGAINST=""
WORKERS=""
CACHE_DIR=""
DEBUG=false
FORCE_REBUILD=false
SNAPSHOT=false
AUTO_YES=false
CHECK_DEPS_ONLY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --against)
            AGAINST="$2"
            shift 2
            ;;
        --quick)
            AGAINST="rust"
            shift
            ;;
        --workers)
            WORKERS="$2"
            shift 2
            ;;
        --cache-dir)
            CACHE_DIR="$2"
            shift 2
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        --force-rebuild)
            FORCE_REBUILD=true
            shift
            ;;
        --snapshot)
            SNAPSHOT=true
            shift
            ;;
        -y|--yes)
            AUTO_YES=true
            shift
            ;;
        --check-deps)
            CHECK_DEPS_ONLY=true
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [[ ! -x "$RUNNER" ]]; then
    echo "Transport interop runner not found at $RUNNER" >&2
    exit 1
fi

# Prefer Homebrew's newer bash so dependency checks pick it up.
if [[ -x /opt/homebrew/bin/bash ]]; then
    export PATH="/opt/homebrew/bin:$PATH"
fi

if [[ "$CHECK_DEPS_ONLY" == true ]]; then
    if [[ -x /opt/homebrew/bin/bash ]]; then
        exec /opt/homebrew/bin/bash "$RUNNER" --check-deps
    else
        exec "$RUNNER" --check-deps
    fi
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker CLI not found in PATH" >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Docker daemon is not reachable. Please start Docker and retry." >&2
    exit 1
fi

# Helper for joining filter patterns with a custom delimiter.
join_by() {
    local IFS="$1"
    shift
    echo "$*"
}

trimmed_targets=()
if [[ -n "$AGAINST" && "$AGAINST" != "all" ]]; then
    IFS=',' read -ra raw_targets <<< "$AGAINST"
    for target in "${raw_targets[@]}"; do
        local_target="$(echo "$target" | xargs)"
        [[ -z "$local_target" ]] && continue
        trimmed_targets+=("$local_target")
    done
fi

filter_patterns=()
if [[ ${#trimmed_targets[@]} -gt 0 ]]; then
    for target in "${trimmed_targets[@]}"; do
        filter_patterns+=("${C_IMPL_ID} x ${target}" "${target} x ${C_IMPL_ID}")
    done
else
    filter_patterns+=("${C_IMPL_ID} x " " x ${C_IMPL_ID}")
fi

if [[ ${#filter_patterns[@]} -eq 0 ]]; then
    echo "No valid peer implementations resolved from --against" >&2
    exit 1
fi

FILTER_VALUE="$(join_by '|' "${filter_patterns[@]}")"
IGNORE_VALUE="${C_IMPL_ID} x ${C_IMPL_ID}"

target_desc="(${C_IMPL_ID} vs ${AGAINST:-all implementations})"
echo "→ Docker daemon is running"
echo "→ Executing transport interop tests ${target_desc}"

cmd=("$RUNNER" "--test-filter" "$FILTER_VALUE" "--test-ignore" "$IGNORE_VALUE")
[[ -n "$WORKERS" ]] && cmd+=("--workers" "$WORKERS")
[[ -n "$CACHE_DIR" ]] && cmd+=("--cache-dir" "$CACHE_DIR")
[[ "$DEBUG" == true ]] && cmd+=("--debug")
[[ "$FORCE_REBUILD" == true ]] && cmd+=("--force-rebuild")
[[ "$SNAPSHOT" == true ]] && cmd+=("--snapshot")
[[ "$AUTO_YES" == true ]] && cmd+=("--yes")

if [[ -x /opt/homebrew/bin/bash ]]; then
    echo "→ Command: /opt/homebrew/bin/bash ${cmd[*]}"
    exec /opt/homebrew/bin/bash "${cmd[@]}"
else
    echo "→ Command: ${cmd[*]}"
    exec "${cmd[@]}"
fi
