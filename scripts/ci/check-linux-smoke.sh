#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
cd "${repo_root}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "error: check-linux-smoke.sh must run on Linux." >&2
  exit 1
fi

for cmd in cmake ctest clang-format clang-tidy cppcheck doxygen git; do
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
  echo "No diff range available; skipping diff-scoped format/doc checks."
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

if [ -n "${range}" ]; then
  doc_headers="$(git diff --name-only "${range}" -- '*.h' | grep -E '^include/multiformats/.+\.h$' || true)"
  if [ -z "${doc_headers}" ]; then
    echo "No changed headers in include/multiformats; skipping doc check."
  else
    doc_gate_dir="$(mktemp -d)"
    trap 'rm -rf "${doc_gate_dir}"' EXIT
    doc_input="$(echo "${doc_headers}" | tr '\n' ' ')"
    doc_doxyfile="${doc_gate_dir}/Doxyfile"

    cat > "${doc_doxyfile}" <<EOF
PROJECT_NAME           = c-libp2p-doc-gate
OUTPUT_DIRECTORY       = ${doc_gate_dir}/out
GENERATE_HTML          = YES
GENERATE_LATEX         = NO
GENERATE_XML           = NO
QUIET                  = YES
WARN_AS_ERROR          = YES
WARN_IF_UNDOCUMENTED   = YES
WARN_IF_INCOMPLETE_DOC = YES
WARN_NO_PARAMDOC       = YES
INPUT                  = ${doc_input}
FILE_PATTERNS          = *.h
RECURSIVE              = NO
EXTRACT_ALL            = YES
EXTRACT_STATIC         = YES
OPTIMIZE_OUTPUT_FOR_C  = YES
ENABLE_PREPROCESSING   = YES
HAVE_DOT               = NO
EOF

    echo "Doxygen doc check scope:"
    echo "${doc_headers}"
    doxygen "${doc_doxyfile}"
    rm -rf "${doc_gate_dir}"
    trap - EXIT
  fi
fi

if [ -n "${range}" ]; then
  changed_multiformats="$(git diff --name-only "${range}" -- '*.c' '*.h' | grep -E '^(src|include|tests)/multiformats/' || true)"
  if [ -z "${changed_multiformats}" ]; then
    echo "No changed files in multiformats scope; skipping MISRA check."
  else
    misra_addon=""
    for candidate in \
      "/usr/share/cppcheck/addons/misra.py" \
      "/usr/lib/cppcheck/addons/misra.py" \
      "/usr/lib/x86_64-linux-gnu/cppcheck/addons/misra.py" \
      "/usr/local/share/cppcheck/addons/misra.py" \
      "/opt/homebrew/share/cppcheck/addons/misra.py" \
      "/opt/homebrew/Cellar/cppcheck/2.19.0/share/cppcheck/addons/misra.py"; do
      if [ -f "${candidate}" ]; then
        misra_addon="${candidate}"
        break
      fi
    done

    if [ -z "${misra_addon}" ]; then
      echo "error: cppcheck MISRA addon (misra.py) not found in known locations." >&2
      exit 1
    fi

    mapfile -t changed_modules < <(printf '%s\n' "${changed_multiformats}" | awk -F/ '{print $3}' | sort -u)
    misra_inputs=()
    for module in "${changed_modules[@]}"; do
      for base in src include tests; do
        module_dir="${base}/multiformats/${module}"
        if [ -d "${module_dir}" ]; then
          misra_inputs+=("${module_dir}")
        fi
      done
    done

    if [ "${#misra_inputs[@]}" -eq 0 ]; then
      echo "No existing multiformats module directories found for MISRA scope; skipping MISRA check."
    else
      echo "MISRA check modules:"
      printf '  - %s\n' "${changed_modules[@]}"
      echo "MISRA analysis paths:"
      printf '  - %s\n' "${misra_inputs[@]}"
      misra_log="$(mktemp)"
      cppcheck \
        --std=c99 \
        --enable=all \
        --check-level=exhaustive \
        --quiet \
        --suppress=missingIncludeSystem \
        --suppress='*:tests/*' \
        --addon="${misra_addon}" \
        -I include \
        "${misra_inputs[@]}" \
        >"${misra_log}" 2>&1 || true

      misra_hits="$(grep -E 'misra violation ' "${misra_log}" || true)"
      rm -f "${misra_log}"
      if [ -n "${misra_hits}" ]; then
        echo "error: MISRA findings detected in multiformats changed-module scope:" >&2
        echo "${misra_hits}" >&2
        exit 1
      fi
    fi
  fi
fi

if [ -n "${range}" ]; then
  cert_sources="$(git diff --name-only "${range}" -- '*.c' | grep -E '^src/multiformats/.+\.c$' || true)"
  if [ -z "${cert_sources}" ]; then
    echo "No changed C sources in src/multiformats; skipping cert-* clang-tidy check."
  else
    if [ ! -f "build/linux-smoke/compile_commands.json" ]; then
      echo "error: missing build/linux-smoke/compile_commands.json for clang-tidy cert check." >&2
      exit 1
    fi

    echo "CERT clang-tidy scope:"
    echo "${cert_sources}"
    while IFS= read -r cert_file; do
      if [ -n "${cert_file}" ]; then
        clang-tidy \
          -quiet \
          -p build/linux-smoke \
          -checks='-*,cert-*' \
          -warnings-as-errors='cert-*' \
          --extra-arg=-Wno-newline-eof \
          --extra-arg=-Wno-error=newline-eof \
          "${cert_file}"
      fi
    done <<< "${cert_sources}"
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
