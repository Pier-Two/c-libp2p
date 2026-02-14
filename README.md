# c-libp2p

**c-libp2p** is an implementation of the [libp2p specification](https://github.com/libp2p/specs) written in C.  The project is still in active development but already provides the building blocks needed for peer-to-peer networking applications.

## Building

c-libp2p uses CMake and should build on Linux, macOS and Windows.  A C compiler that supports the C11 standard is required.

### Clone the repository

```sh
git clone --recursive https://github.com/Pier-Two/c-libp2p.git
cd c-libp2p
```

The `--recursive` flag ensures that all third-party submodules are fetched.

### Linux / macOS

```sh
mkdir build
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

Sanitizers can be enabled with `-DENABLE_SANITIZERS=ON` and additional flags in `SANITIZERS`.  Stress tests for the TCP module are built when `-DENABLE_STRESS_TESTS=ON` is passed.

### Windows

A recent Visual Studio with CMake support is recommended.  From the *x64 Native Tools* command prompt run:

```bat
mkdir build
cmake -S . -B build -G "Visual Studio 16 2019" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release
```

When building shared libraries on Windows the produced DLLs are copied next to the test executables automatically.

## CI lanes

Validation is split into two lanes:

- Fast lane (`.github/workflows/ci-fast.yml`, required for PRs):
  - `macos-smoke`
  - `linux-smoke`
  - `windows-smoke`
- Full lane (`.github/workflows/ci-full.yml`, runs on `main`, nightly, and manual dispatch):
  - `macos-full`
  - `linux-gcc-full`
  - `linux-clang-full`
  - `linux-sanitizers` (ASan/UBSan)
  - `windows-full`

The lane presets are versioned in `CMakePresets.json` and can be run locally:

```sh
# fast lane (macOS example)
cmake --preset macos-smoke
cmake --build --preset macos-smoke
ctest --preset macos-smoke

# full lane (macOS example)
cmake --preset macos-full
cmake --build --preset macos-full
ctest --preset macos-full
```

For Windows validation from non-Windows development machines, trigger and monitor the full lane with GitHub CLI:

```sh
gh workflow run ci-full.yml --ref <branch>
gh run list --workflow ci-full.yml
gh run watch <run-id>
gh run view <run-id> --log
```

## Local pre-push fast-lane hook (macOS/Linux)

Install the repository-managed git hooks:

```sh
scripts/dev/install-hooks.sh
```

This configures `core.hooksPath` to `.githooks` and enables a `pre-push` hook that runs the same macOS/Linux fast-lane checks used by CI.

On Linux, fast-lane checks include:
- clang-format diff check for changed `src/`, `include/`, and `tests` C files.
- a targeted Doxygen documentation gate for changed headers in `include/multiformats/unsigned_varint/` and `include/multiformats/multicodec/` (`WARN_IF_UNDOCUMENTED=YES`, `WARN_AS_ERROR=YES`).
- a targeted MISRA add-on check for rewritten multiformats scope (`unsigned_varint` + `multicodec`) with documented Rule 8.7 advisory suppressions for exported API symbols.
- a targeted `clang-tidy` CERT gate (`-checks=-*,cert-*`, warnings-as-errors) for changed C sources in `src/multiformats/{unsigned_varint,multicodec}`.
- `cppcheck` smoke static analysis for core scope.

Manual local run:

```sh
# Auto-detect host platform (macOS or Linux)
scripts/dev/run-fast-lane-local.sh

# Force a specific platform script
scripts/dev/run-fast-lane-local.sh --platform macos
scripts/dev/run-fast-lane-local.sh --platform linux
```

To bypass the hook for one push:

```sh
LIBP2P_SKIP_FAST_HOOK=1 git push
```

## Project Structure

- `src/` – library source code
- `include/` – public headers
- `tests/` – unit tests
- `benchmarks/` – optional benchmarks
- `docs/` – user guides and examples

Detailed documentation is available under [docs/](docs/README.md).

## Third-party libraries

c-libp2p bundles several third-party projects under `external/`:

- [libtomcrypt](https://github.com/libtom/libtomcrypt) and [libtommath](https://github.com/libtom/libtommath) – [LibTom License](http://unlicense.org/)
- [secp256k1](https://github.com/bitcoin-core/secp256k1) – [MIT License](https://opensource.org/licenses/MIT)
- [sha3](https://github.com/pablotron/sha3) – [MIT-0 License](https://opensource.org/license/mit-0/)
- [WjCryptLib](https://github.com/WaterJuice/WjCryptLib) – [Unlicense](http://unlicense.org/)
- [c20p1305](https://github.com/wg/c20p1305) – [MIT License](https://opensource.org/licenses/MIT)
- [libeddsa](https://github.com/phlay/libeddsa) – [Unlicense](http://unlicense.org/)
- [noise-c](https://github.com/uink45/noise-c) – [MIT License](https://opensource.org/licenses/MIT)

Please refer to each submodule for license details.

## License

The code in this repository is licensed under the [MIT License](LICENSE-MIT.md).
