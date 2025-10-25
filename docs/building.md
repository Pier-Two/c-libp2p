# Building c-libp2p

c-libp2p uses CMake (3.10 or newer) and a C11-capable compiler. All third-party
code lives in git submodules, so a single clone step prepares everything that is
needed to build the library and run the unit tests.

## 1. Fetch the sources

```sh
git clone --recursive https://github.com/Pier-Two/c-libp2p.git
cd c-libp2p
```

The `--recursive` flag ensures that crypto primitives and other vendored
components under `external/` are checked out alongside the main tree.

## 2. Configure the build

```sh
cmake -S . -B build
```

Key defaults:

- `CMAKE_BUILD_TYPE` defaults to `Debug` for a better debugging experience.
- `BUILD_SHARED_LIBS` defaults to `ON`, producing shared objects alongside static
  archives. Pass `-DBUILD_SHARED_LIBS=OFF` if you prefer static linking.
- Coverage instrumentation is enabled by default (`-DENABLE_COVERAGE=ON`). Set
  it to `OFF` when building for production toolchains that do not support the
  instrumentation flags.

Useful toggles when invoking CMake:

- `-DENABLE_SANITIZERS=ON` to compile with Address/Undefined sanitizers. The
  specific set can be overridden with `-DSANITIZERS=address;undefined;thread`.
- `-DENABLE_CLANG_TIDY=ON`, `-DENABLE_CPPCHECK=ON`, or
  `-DENABLE_IWYU=ON` to wire optional static-analysis passes on project sources.
- `-DENABLE_STRESS_TESTS=ON` to build long-running TCP stress tests.

Re-run the `cmake -S . -B build ...` command whenever you toggle options.

## 3. Build and test

```sh
cmake --build build
ctest --test-dir build
```

By default the resulting libraries are written under `build/lib/` and the sample
binaries/tests under `build/bin/` and `build/tests/`. Use the usual CMake
options (`-DCMAKE_INSTALL_PREFIX`, `cmake --install build`, etc.) if you intend
to stage the headers and libraries elsewhere.

`ctest` inherits the environment from the build tree. Add `-j` to run tests in
parallel or `-V` for verbose output when diagnosing failures.

## 4. Optional convenience targets

If `clang-format` is available, CMake generates `clang_format` and
`clang_format_check` targets limited to the project sources. Invoke them with:

```sh
cmake --build build --target clang_format
```

Use `cmake --build build --target clean` to remove compiled objects, or simply
delete the `build/` directory to start over.

## Platform notes

- **Linux / macOS** – Clang and GCC toolchains are both supported. On macOS the
  build system automatically matches the host architecture unless overridden via
  `CMAKE_OSX_ARCHITECTURES`.
- **Windows** – Configure from the *x64 Native Tools* prompt. Visual Studio 2019
  (or newer) works out of the box:
  ```bat
  mkdir build
  cmake -S . -B build -G "Visual Studio 16 2019" -A x64
  cmake --build build --config Release
  ctest --test-dir build -C Release
  ```

That’s all that is required to get a working libp2p C library plus its test
suite. Once the build completes, head over to the [overview](overview.md) to see
how the pieces fit together.
