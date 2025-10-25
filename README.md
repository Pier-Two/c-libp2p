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
