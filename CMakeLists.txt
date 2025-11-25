# CMake minimum required version.
cmake_minimum_required(VERSION 3.10)

# Build using shared libraries by default
option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

# Project metadata.
project(libp2p
    VERSION 0.1
    DESCRIPTION "C Libp2p implementation"
    LANGUAGES C
)

if(NOT DEFINED OPENSSL_ROOT_DIR AND DEFINED ENV{OPENSSL_ROOT_DIR})
  set(OPENSSL_ROOT_DIR "$ENV{OPENSSL_ROOT_DIR}" CACHE PATH "Path to custom OpenSSL installation" FORCE)
endif()

if(OPENSSL_ROOT_DIR)
  list(PREPEND CMAKE_PREFIX_PATH "${OPENSSL_ROOT_DIR}")
  list(PREPEND CMAKE_LIBRARY_PATH "${OPENSSL_ROOT_DIR}/lib")
  list(PREPEND CMAKE_INCLUDE_PATH "${OPENSSL_ROOT_DIR}/include")
endif()

find_package(BISON REQUIRED)
find_package(FLEX REQUIRED)

# Default to Debug builds for better debugging experience unless explicitly overridden
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# Additional multiselect IO adapter test
add_executable(test_protocol_multiselect_io
    tests/protocol/multiselect/test_protocol_multiselect_io.c
)
target_link_libraries(test_protocol_multiselect_io PRIVATE
    protocol_multiselect
    libp2p_unified
    Threads::Threads
)
set_target_properties(test_protocol_multiselect_io PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME Testprotocol_multiselect_io COMMAND test_protocol_multiselect_io)
set_tests_properties(Testprotocol_multiselect_io PROPERTIES TIMEOUT 20)

# Always compile with debug symbols and no optimizations to improve LLDB experience
# (This applies to all targets below; adjust if you want per-target control.)
add_compile_options(-O0 -g)

if(APPLE)
  string(TOLOWER "${CMAKE_HOST_SYSTEM_PROCESSOR}" _host_arch)
  set(_prefer_arm64 OFF)
  if(_host_arch STREQUAL "arm64")
    set(_prefer_arm64 ON)
  else()
    execute_process(COMMAND /usr/sbin/sysctl -n hw.optional.arm64
      OUTPUT_VARIABLE _hw_arm64
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET)
    if(_hw_arm64 STREQUAL "1")
      set(_prefer_arm64 ON)
    endif()
  endif()
  set(_target_macos_arch "${CMAKE_SYSTEM_PROCESSOR}")
  if(_prefer_arm64)
    set(_target_macos_arch "arm64")
  endif()
  if(NOT DEFINED CMAKE_OSX_ARCHITECTURES OR "${CMAKE_OSX_ARCHITECTURES}" STREQUAL "")
    # Default to the native host architecture; this avoids Rosetta on Apple Silicon.
    set(CMAKE_OSX_ARCHITECTURES "${_target_macos_arch}" CACHE STRING "Build architectures for macOS" FORCE)
  elseif(_prefer_arm64 AND NOT (CMAKE_OSX_ARCHITECTURES MATCHES "(^|;)arm64($|;)"))
    # When configuring under Rosetta, the cache may carry over x86_64—force arm64 to avoid timeouts.
    set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "Build architectures for macOS" FORCE)
  endif()
  if(_prefer_arm64)
    set(ED448_ARCH "arch_ref64" CACHE STRING "Specify Ed448-Goldilocks arch" FORCE)
    set(SECP256K1_ASM OFF CACHE STRING "" FORCE)
    set(PTLS_WITH_FUSION OFF CACHE BOOL "" FORCE)
    set(WITH_FUSION OFF CACHE BOOL "" FORCE)
    if(EXISTS "/opt/homebrew/lib/libcrypto.dylib")
      set(OPENSSL_ROOT_DIR "/opt/homebrew" CACHE PATH "" FORCE)
      set(OPENSSL_INCLUDE_DIR "/opt/homebrew/include" CACHE PATH "" FORCE)
      set(OPENSSL_CRYPTO_LIBRARY "/opt/homebrew/lib/libcrypto.dylib" CACHE FILEPATH "" FORCE)
      set(OPENSSL_SSL_LIBRARY "/opt/homebrew/lib/libssl.dylib" CACHE FILEPATH "" FORCE)
    endif()
  endif()
  message(STATUS "Building for macOS architecture: ${CMAKE_OSX_ARCHITECTURES}")

  # Ensure early-defined targets (like test_protocol_multiselect_io) inherit the
  # configured slice instead of falling back to CMake's default architecture.
  if(TARGET test_protocol_multiselect_io AND CMAKE_OSX_ARCHITECTURES)
    set_target_properties(test_protocol_multiselect_io PROPERTIES
      OSX_ARCHITECTURES "${CMAKE_OSX_ARCHITECTURES}")
  endif()
endif()

option(ENABLE_SANITIZERS "Enable Address, UndefinedBehavior, Thread, etc. Sanitizers" OFF)
set(SANITIZERS "address;undefined" CACHE STRING "List of sanitizers to enable (semicolon-separated)")

# QUIC transport vendoring
option(LIBP2P_VENDOR_PICOQUIC "Build and expose picoquic vendor target" ON)

if(NOT LIBP2P_VENDOR_PICOQUIC)
    message(FATAL_ERROR "Bundled picoquic is required; configure with -DLIBP2P_VENDOR_PICOQUIC=ON.")
endif()

if(LIBP2P_VENDOR_PICOQUIC AND NOT EXISTS "${PROJECT_SOURCE_DIR}/external/picoquic/CMakeLists.txt")
    message(FATAL_ERROR "LIBP2P_VENDOR_PICOQUIC is ON, but the picoquic submodule is missing. Run `git submodule update --init --recursive`.")
endif()

# ---------------------------------------------------------------------
# Static‑analysis / coverage options
# ---------------------------------------------------------------------
option(ENABLE_CLANG_TIDY "Run clang‑tidy static analysis" OFF)
option(ENABLE_CPPCHECK   "Run cppcheck static analysis"  OFF)
option(ENABLE_IWYU       "Run include‑what‑you‑use"      OFF)
option(ENABLE_COVERAGE   "Enable code-coverage flags"    ON)
option(ENABLE_STRESS_TESTS "Build and run high‑load stress tests" OFF)

if(ENABLE_SANITIZERS)
    set(_sanitizers ${SANITIZERS})
    list(JOIN _sanitizers "," _san_opt)
    message(STATUS "Building with sanitizers: ${_san_opt}")

    add_compile_options(-fsanitize=${_san_opt} -fno-omit-frame-pointer)
    add_link_options(-fsanitize=${_san_opt})

    if(TARGET test_protocol_multiselect_io)
        target_compile_options(test_protocol_multiselect_io PRIVATE -fsanitize=${_san_opt} -fno-omit-frame-pointer)
        target_link_options(test_protocol_multiselect_io PRIVATE -fsanitize=${_san_opt})
    endif()

    # With sanitizers enabled, inline assembly in secp256k1 conflicts with
    # instrumentation on some toolchains (register pressure). Disable ASM for
    # the submodule to ensure a reliable ASan/UBSan build.
    set(SECP256K1_ASM OFF CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------
# Static analysis integrations
# ---------------------------------------------------------------------
if(ENABLE_CLANG_TIDY)
    # Discover clang-tidy, but do NOT apply globally. We'll attach it only to
    # this project's library targets to avoid touching submodules.
    find_program(CLANG_TIDY_EXE NAMES clang-tidy
        HINTS
            /opt/homebrew/opt/llvm/bin
            /usr/local/opt/llvm/bin
    )
    if(CLANG_TIDY_EXE)
        set(LIBP2P_CLANG_TIDY "${CLANG_TIDY_EXE};--quiet")
        message(STATUS "clang-tidy enabled (project libraries only): ${CLANG_TIDY_EXE}")
    else()
        message(WARNING "clang-tidy requested but not found – disabling")
    endif()
endif()

# clang-format: provide format and format-check targets for this project only
find_program(CLANG_FORMAT_EXE NAMES clang-format
    HINTS
        /opt/homebrew/opt/llvm/bin
        /usr/local/opt/llvm/bin
)
if(CLANG_FORMAT_EXE)
    # Only include our own sources/headers (exclude submodules)
    file(GLOB_RECURSE LIBP2P_FORMAT_FILES
        CONFIGURE_DEPENDS
        "${PROJECT_SOURCE_DIR}/src/*"
        "${PROJECT_SOURCE_DIR}/include/*"
    )
    # Keep only .c/.h
    list(FILTER LIBP2P_FORMAT_FILES INCLUDE REGEX "\\.(c|h)$")

    if(LIBP2P_FORMAT_FILES)
        add_custom_target(clang_format
            COMMAND ${CLANG_FORMAT_EXE} -i ${LIBP2P_FORMAT_FILES}
            COMMENT "Running clang-format on libp2p sources (src/, include/)"
            VERBATIM
        )

        add_custom_target(clang_format_check
            COMMAND ${CLANG_FORMAT_EXE} --dry-run --Werror ${LIBP2P_FORMAT_FILES}
            COMMENT "Checking clang-format on libp2p sources (src/, include/)"
            VERBATIM
        )
    endif()
else()
    message(STATUS "clang-format not found – format targets unavailable")
endif()

# ---------------------------------------------
# libp2p_metrics (extracted from libp2p_unified)
# ---------------------------------------------
add_library(libp2p_metrics
    src/util/metrics.c
)
target_include_directories(libp2p_metrics PUBLIC ${PROJECT_SOURCE_DIR}/include)

# ---------------------------------------------
# libp2p_log (shared logging implementation)
# ---------------------------------------------
add_library(libp2p_log
    src/util/log.c
)
target_include_directories(libp2p_log PUBLIC ${PROJECT_SOURCE_DIR}/include)

if(ENABLE_CPPCHECK)
    find_program(CPPCHECK_EXE NAMES cppcheck)
    if(CPPCHECK_EXE)
        set(CMAKE_C_CPPCHECK "${CPPCHECK_EXE};--enable=all;--inconclusive;--std=c99;--quiet;--error-exitcode=1")
        message(STATUS "cppcheck enabled: ${CPPCHECK_EXE}")
    else()
        message(WARNING "cppcheck requested but not found – disabling")
    endif()
endif()

if(ENABLE_IWYU)
    find_program(IWYU_EXE NAMES include-what-you-use iwyu)
    if(IWYU_EXE)
        set(CMAKE_C_INCLUDE_WHAT_YOU_USE "${IWYU_EXE}")
        message(STATUS "include-what-you-use enabled: ${IWYU_EXE}")
    else()
        message(WARNING "include-what-you-use requested but not found – disabling")
    endif()
endif()

# ---------------------------------------------------------------------
# Code coverage
# ---------------------------------------------------------------------
if(ENABLE_COVERAGE)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        add_compile_options(-O0 -fprofile-instr-generate -fcoverage-mapping)
        add_link_options(-fprofile-instr-generate)
        message(STATUS "LLVM profile instrumentation enabled (Clang)")
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
        add_compile_options(-O0 --coverage)
        add_link_options(--coverage)
        message(STATUS "gcov coverage instrumentation enabled (GCC)")
    else()
        message(WARNING "Code coverage currently supported only with GCC or Clang")
    endif()
endif()

# Pull in pthread/C11‐threads
find_package(Threads REQUIRED)

# ------------------------------------------------
# detect explicit_bzero() in <string.h>
# ------------------------------------------------
include(CheckFunctionExists)
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)

if(HAVE_EXPLICIT_BZERO)
  # system has it—tell the compiler to skip our fallback
  add_compile_definitions(HAVE_EXPLICIT_BZERO=1)
endif()

# Add the cmake directory to the module path
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

# Set the C standard.
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_definitions(_GNU_SOURCE)

# Set output directories for executables, libraries, and archives.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(TARGET libp2p_metrics)
    # Ensure the metrics library lands alongside the other shared objects so
    # packaging logic (e.g. interop Docker image) can pick it up reliably.
    set_target_properties(libp2p_metrics PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    )
endif()

if(TARGET libp2p_log)
    # Align the log shim with the rest of the shared objects so packaging can copy once.
    set_target_properties(libp2p_log PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    )
endif()

# Include public headers.
include_directories(BEFORE ${PROJECT_SOURCE_DIR}/include/protocol/tcp)
include_directories(${PROJECT_SOURCE_DIR}/include)

# (force the cache so that the secp256k1 CMakeLists picks them up as OFF)
set(SECP256K1_BUILD_TESTS            OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK        OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CTIME_TESTS      OFF CACHE BOOL "" FORCE)

## Helper to add submodules without inheriting/top‑level tests
function(_add_subdirectory_no_tests dir)
  # Preserve current cached BUILD_TESTING (may be undefined)
  if(DEFINED BUILD_TESTING)
    set(_saved_BUILD_TESTING "${BUILD_TESTING}")
  else()
    set(_saved_BUILD_TESTING "__undef__")
  endif()
  # Force tests off for the subproject
  set(BUILD_TESTING OFF CACHE BOOL "Build tests (forced OFF for submodules)" FORCE)
  # Keep submodules out of the default build and CTest recursion.
  # EXCLUDE_FROM_ALL prevents the directory from contributing to the top‑level
  # ALL target and typically omits it from CTest's generated subdirs list.
  add_subdirectory(${dir} EXCLUDE_FROM_ALL)
  # Restore previous cache state
  if(_saved_BUILD_TESTING STREQUAL "__undef__")
    unset(BUILD_TESTING CACHE)
  else()
    set(BUILD_TESTING "${_saved_BUILD_TESTING}" CACHE BOOL "Build tests" FORCE)
  endif()

  # Remove any stale CTest test files that may have been generated by the
  # submodule in a previous configure. Otherwise, CTest can still discover and
  # run those tests by recursing into the subdir.
  file(GLOB_RECURSE _stale_ctest_files
       RELATIVE "${CMAKE_BINARY_DIR}"
       "${CMAKE_BINARY_DIR}/${dir}/CTestTestfile.cmake")
  if(_stale_ctest_files)
    foreach(_f IN LISTS _stale_ctest_files)
      file(REMOVE "${CMAKE_BINARY_DIR}/${_f}")
    endforeach()
  endif()
endfunction()

# Add secp256k1 submodule.
_add_subdirectory_no_tests(external/secp256k1)

# Add libtommath submodule.
#
# On macOS with Apple Clang 17, linking libtommath as a shared library has been
# observed to crash the system linker (Segmentation fault: 11) on some setups.
# To avoid this toolchain issue, force libtommath to build as a static library
# and ensure it is position‑independent so it can be linked into shared libs.
set(_saved_BUILD_SHARED_LIBS "${BUILD_SHARED_LIBS}")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build using shared libraries" FORCE)
_add_subdirectory_no_tests(external/libtommath)
set(BUILD_SHARED_LIBS "${_saved_BUILD_SHARED_LIBS}" CACHE BOOL "Build using shared libraries" FORCE)
set(libtommath_DIR "${CMAKE_BINARY_DIR}/external/libtommath")

# Workarounds for libtommath build under our global -O0/-g settings.
if(TARGET libtommath)
  # Ensure codegen keeps dead‑code elimination needed by MP_HAS(...)
  target_compile_options(libtommath PRIVATE -O1 -g)
  # Allow static lib to link into shared libraries cleanly
  set_target_properties(libtommath PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

# Add libtomcrypt submodule.
_add_subdirectory_no_tests(external/libtomcrypt)
target_compile_definitions(libtomcrypt PRIVATE
    USE_LTM
    LTM_DESC
    ed25519_export=ltc_ed25519_export
    ed25519_import=ltc_ed25519_import
    ed25519_import_pkcs8=ltc_ed25519_import_pkcs8
    ed25519_import_raw=ltc_ed25519_import_raw
    ed25519_import_x509=ltc_ed25519_import_x509
    ed25519_make_key=ltc_ed25519_make_key
    ed25519_sign=ltc_ed25519_sign
    ed25519_verify=ltc_ed25519_verify
    ed25519ctx_verify=ltc_ed25519ctx_verify
    ed25519ph_verify=ltc_ed25519ph_verify
    x25519_export=ltc_x25519_export
    x25519_import=ltc_x25519_import
    x25519_import_pkcs8=ltc_x25519_import_pkcs8
    x25519_import_raw=ltc_x25519_import_raw
    x25519_import_x509=ltc_x25519_import_x509
    x25519_make_key=ltc_x25519_make_key
    x25519_shared_secret=ltc_x25519_shared_secret
)

# Add noise-c submodule with crypto backends disabled.
set(USE_LIBSODIUM OFF CACHE BOOL "" FORCE)
set(USE_OPENSSL OFF CACHE BOOL "" FORCE)
_add_subdirectory_no_tests(external/noise-c)
set_target_properties(noiseprotocol PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(LIBP2P_VENDOR_PICOQUIC)
    # Add picoquic QUIC stack with bundled picotls.
    set(PICOQUIC_FETCH_PTLS ON CACHE BOOL "Fetch Picotls when configuring picoquic" FORCE)
    # Temporarily suppress pkg-config discovery so picotls does not enable
    # optional Brotli (or other) system libs that may not match our arch.
    # We'll restore the environment after adding the subdirectory.
    set(_SAVED_PKG_CONFIG_PATH "$ENV{PKG_CONFIG_PATH}")
    set(_SAVED_PKG_CONFIG_LIBDIR "$ENV{PKG_CONFIG_LIBDIR}")
    set(ENV{PKG_CONFIG_PATH} "")
    set(ENV{PKG_CONFIG_LIBDIR} "${CMAKE_BINARY_DIR}/__no_pkgconfig__")
    set(picoquic_BUILD_TESTS OFF CACHE BOOL "Build picoquic tests" FORCE)
    set(BUILD_DEMO OFF CACHE BOOL "Build picoquic demo binaries" FORCE)
    set(BUILD_HTTP OFF CACHE BOOL "Build picoquic HTTP helpers" FORCE)
    set(BUILD_LOGLIB OFF CACHE BOOL "Build picoquic log helpers" FORCE)
    set(BUILD_LOGREADER OFF CACHE BOOL "Build picoquic log reader" FORCE)
    set(WITH_OPENSSL ON CACHE BOOL "Use OpenSSL backend for picoquic" FORCE)
    set(WITH_MBEDTLS OFF CACHE BOOL "Disable mbedTLS backend for picoquic" FORCE)
    _add_subdirectory_no_tests(external/picoquic)
    # Restore pkg-config search path
    set(ENV{PKG_CONFIG_PATH} "${_SAVED_PKG_CONFIG_PATH}")
    set(ENV{PKG_CONFIG_LIBDIR} "${_SAVED_PKG_CONFIG_LIBDIR}")
    if(TARGET picoquic-core)
        set_target_properties(picoquic-core PROPERTIES POSITION_INDEPENDENT_CODE ON)
    endif()

    add_library(libp2p_quic_vendor INTERFACE)
    target_link_libraries(libp2p_quic_vendor INTERFACE picoquic-core)
endif()

# ---------------------------------------------------------------------------
# noise-protoc host generator for gossipsub protobuf schemas
# ---------------------------------------------------------------------------
set(NOISE_PROTOC_DIR ${PROJECT_SOURCE_DIR}/external/noise-c/tools/protoc)
set(NOISE_PROTOC_BUILD_DIR ${CMAKE_BINARY_DIR}/noise_protoc)
file(MAKE_DIRECTORY ${NOISE_PROTOC_BUILD_DIR})

BISON_TARGET(noise_protoc_parser
    ${NOISE_PROTOC_DIR}/proto3-grammar.y
    ${NOISE_PROTOC_BUILD_DIR}/proto3-grammar.c
    DEFINES_FILE ${NOISE_PROTOC_BUILD_DIR}/proto3-grammar.h
)
FLEX_TARGET(noise_protoc_lexer
    ${NOISE_PROTOC_DIR}/proto3-lexer.l
    ${NOISE_PROTOC_BUILD_DIR}/proto3-lexer.c
)
ADD_FLEX_BISON_DEPENDENCY(noise_protoc_lexer noise_protoc_parser)

add_executable(noise_protoc
    ${NOISE_PROTOC_DIR}/main.c
    ${NOISE_PROTOC_DIR}/proto3-ast.c
    ${NOISE_PROTOC_DIR}/proto3-generate-c.c
    ${BISON_noise_protoc_parser_OUTPUTS}
    ${FLEX_noise_protoc_lexer_OUTPUTS}
)
target_include_directories(noise_protoc PRIVATE
    ${NOISE_PROTOC_DIR}
    ${NOISE_PROTOC_BUILD_DIR}
)

set(GOSSIPSUB_PROTO_SRC ${PROJECT_SOURCE_DIR}/src/protocol/gossipsub/proto/rpc.proto)
set(GOSSIPSUB_PROTO_GEN_DIR ${PROJECT_SOURCE_DIR}/src/protocol/gossipsub/proto/gen)
set(GOSSIPSUB_PROTO_C ${GOSSIPSUB_PROTO_GEN_DIR}/gossipsub_rpc.pb.c)
set(GOSSIPSUB_PROTO_H ${GOSSIPSUB_PROTO_GEN_DIR}/gossipsub_rpc.pb.h)

add_custom_command(
    OUTPUT ${GOSSIPSUB_PROTO_C} ${GOSSIPSUB_PROTO_H}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${GOSSIPSUB_PROTO_GEN_DIR}
    COMMAND $<TARGET_FILE:noise_protoc> --output-c ${GOSSIPSUB_PROTO_C} --output-h ${GOSSIPSUB_PROTO_H} ${GOSSIPSUB_PROTO_SRC}
    DEPENDS ${GOSSIPSUB_PROTO_SRC} noise_protoc
    COMMENT "Generating gossipsub RPC protobuf sources"
    VERBATIM
)

add_custom_target(gossipsub_proto
    DEPENDS ${GOSSIPSUB_PROTO_C} ${GOSSIPSUB_PROTO_H}
)

# Add libeddsa submodule.
_add_subdirectory_no_tests(external/libeddsa)

# ---------------------------------------------
# Helper function for adding a module.
# ---------------------------------------------
#
# Parameters:
#   MODULE_NAME   - Name of the library target.
#   MODULE_SOURCE - Source file for the library.
#   TEST_SOURCE   - Source file for the test executable.
#   BENCH_SOURCE  - (Optional) Source file for the benchmark executable.
#   PRIVATE_DIR   - (Optional) Relative path for additional private include directories.
#
function(add_module MODULE_NAME MODULE_SOURCE TEST_SOURCE BENCH_SOURCE PRIVATE_DIR)
    # Create the library (shared if BUILD_SHARED_LIBS=ON).
    add_library(${MODULE_NAME} ${MODULE_SOURCE})
    target_include_directories(${MODULE_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)
    if(NOT "${PRIVATE_DIR}" STREQUAL "")
        target_include_directories(${MODULE_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/${PRIVATE_DIR})
    endif()
    target_link_libraries(${MODULE_NAME} PUBLIC libp2p_log)

    # Attach clang-tidy to project libraries only (not to tests/benchmarks).
    if(ENABLE_CLANG_TIDY AND LIBP2P_CLANG_TIDY)
        set_target_properties(${MODULE_NAME} PROPERTIES C_CLANG_TIDY "${LIBP2P_CLANG_TIDY}")
    endif()

    # Create the test executable.
    if(NOT "${TEST_SOURCE}" STREQUAL "")
        add_executable(test_${MODULE_NAME} ${TEST_SOURCE})
        target_link_libraries(test_${MODULE_NAME} PRIVATE ${MODULE_NAME})
        set_target_properties(test_${MODULE_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
        )
        add_test(NAME Test${MODULE_NAME} COMMAND test_${MODULE_NAME})

        # On Windows, copy all produced DLLs from bin/ into the test folder
        if (WIN32 AND BUILD_SHARED_LIBS)
          add_custom_command(TARGET test_${MODULE_NAME}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory
              ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
              $<TARGET_FILE_DIR:test_${MODULE_NAME}>
          )
        endif()
        set_tests_properties(Test${MODULE_NAME} PROPERTIES TIMEOUT 10)
    endif()

    # Create the benchmark executable if provided.
    if(NOT "${BENCH_SOURCE}" STREQUAL "")
        add_executable(bench_${MODULE_NAME} ${BENCH_SOURCE})
        target_link_libraries(bench_${MODULE_NAME} PRIVATE ${MODULE_NAME})
        set_target_properties(bench_${MODULE_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/benchmarks
        )
    endif()
endfunction()

# Enable testing with CTest.
enable_testing()

# ---------------------------------------------
# ThreadSanitizer convenience target
# ---------------------------------------------
# Provides: `cmake --build build --target tsan`
# This configures a separate build directory with TSan enabled,
# builds, then runs the full ctest suite under TSan.
add_custom_target(tsan
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/tsan
    COMMAND ${CMAKE_COMMAND}
            -S ${CMAKE_SOURCE_DIR}
            -B ${CMAKE_BINARY_DIR}/tsan
            -DCMAKE_BUILD_TYPE=Debug
            -DENABLE_SANITIZERS=ON
            -DSANITIZERS=thread
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/tsan --parallel
    COMMAND ${CMAKE_COMMAND} -E env
            TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1:report_signal_unsafe=1
            ${CMAKE_CTEST_COMMAND} --output-on-failure --test-dir ${CMAKE_BINARY_DIR}/tsan
    COMMENT "Configure, build, and run tests with ThreadSanitizer"
)

# ---------------------------------------------
# unified API (headers + initial skeleton)
# ---------------------------------------------

add_library(libp2p_unified
    src/host/host_core.c
    src/host/host_listen.c
    src/host/host_dial.c
    src/host/conn_pool.c
    src/host/host_upgrader_helpers.c
    src/host/host_events.c
    src/host/component_registry.c
    
    src/host/host_registry.c
    src/host/host_introspect.c
    src/host/publish_service.c
    src/protocol/identify/identify_service.c
    src/protocol/identify/identify_public.c
    src/host/events_bus.c
    src/host/callback_exec.c
    src/host/proto_select.c
    src/host/host_builder.c
    src/runtime/runtime.c
    src/stream/stream.c
    src/stream/io_adapter.c
    src/protocol/muxer/yamux/yamux_stream_adapter.c
    src/protocol/muxer/mplex/mplex_io_adapter.c
    src/protocol/muxer/mplex/mplex_stream_adapter.c
    src/util/lpmsg.c
    src/util/debug_trace.c
    src/util/peerstore.c
    src/util/managers.c
    src/util/error_map.c
    src/transport/transport_public.c
    src/security/security_public.c
    src/muxer/muxer_public.c
)
target_include_directories(libp2p_unified PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_include_directories(libp2p_unified PRIVATE ${PROJECT_SOURCE_DIR}/src/host)
if(ENABLE_CLANG_TIDY AND LIBP2P_CLANG_TIDY)
    set_target_properties(libp2p_unified PROPERTIES C_CLANG_TIDY "${LIBP2P_CLANG_TIDY}")
endif()
target_link_libraries(libp2p_unified
    PUBLIC
        libp2p_log
        libp2p_metrics
        protocol_tcp
        protocol_noise
        protocol_yamux
        protocol_mplex
        protocol_multiselect
        protocol_identify
        transport_upgrader
        unsigned_varint
        peer_id_ed25519
        peer_id_secp256k1
        peer_id_rsa
        peer_id_ecdsa
)

# LP over IO test
add_executable(test_lpmsg_io
    tests/util/test_lpmsg_io.c
)
target_link_libraries(test_lpmsg_io PRIVATE libp2p_unified Threads::Threads)
set_target_properties(test_lpmsg_io PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME TestLPmsgIO COMMAND test_lpmsg_io)
set_tests_properties(TestLPmsgIO PROPERTIES TIMEOUT 10)

# Peerstore basic API test
add_executable(test_peerstore
    tests/util/test_peerstore.c
)
target_link_libraries(test_peerstore PRIVATE libp2p_unified)
set_target_properties(test_peerstore PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME TestPeerstoreBasic COMMAND test_peerstore)
set_tests_properties(TestPeerstoreBasic PROPERTIES TIMEOUT 10)

# Event deepcopy/free symmetry test
add_executable(test_event_deepcopy_free
    tests/host/test_event_deepcopy_free.c
)
target_link_libraries(test_event_deepcopy_free PRIVATE libp2p_unified)
set_target_properties(test_event_deepcopy_free PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME TestEventDeepcopyFree COMMAND test_event_deepcopy_free)
set_tests_properties(TestEventDeepcopyFree PROPERTIES TIMEOUT 10)

# Metrics basic API test
add_executable(test_metrics_basic
    tests/util/test_metrics_basic.c
)
target_link_libraries(test_metrics_basic PRIVATE libp2p_unified Threads::Threads)
set_target_properties(test_metrics_basic PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME TestMetricsBasic COMMAND test_metrics_basic)
set_tests_properties(TestMetricsBasic PROPERTIES TIMEOUT 10)

# Example using the unified API
add_executable(example_unified_echo examples/unified_echo.c)
target_link_libraries(example_unified_echo PRIVATE libp2p_unified)

# Interop tool (C implementation)
add_executable(interop-c src/interop/interop.c)
target_link_libraries(interop-c PRIVATE libp2p_unified protocol_ping)
set_target_properties(interop-c PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

add_executable(gossipsub-interop
    src/interop/gossipsub/gossipsub_interop.c
    src/interop/gossipsub/jsmn.c
)
target_link_libraries(gossipsub-interop PRIVATE libp2p_unified protocol_gossipsub)
target_include_directories(gossipsub-interop PRIVATE
    ${PROJECT_SOURCE_DIR}/src/interop/gossipsub
    ${PROJECT_SOURCE_DIR}/external/libeddsa/lib
)
if(UNIX)
    target_link_libraries(gossipsub-interop PRIVATE m)
endif()
set_target_properties(gossipsub-interop PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# ---------------------------------------------
# host events tests
# ---------------------------------------------
add_executable(test_host_events_dial_errors
    tests/host/test_host_events_dial_errors.c)
target_link_libraries(test_host_events_dial_errors PRIVATE libp2p_unified Threads::Threads)
set_target_properties(test_host_events_dial_errors PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME TestHostEventsDialErrors COMMAND test_host_events_dial_errors)
set_tests_properties(TestHostEventsDialErrors PROPERTIES TIMEOUT 30)

# Resource Manager removed to keep parity with rust-libp2p.

# Connection manager / outbound limits test (temporarily disabled due to
# non-deterministic timing of stream registration on some platforms)
# add_executable(test_conn_manager_outbound_limits
#     tests/host/test_conn_manager_outbound_limits.c)
# target_link_libraries(test_conn_manager_outbound_limits PRIVATE libp2p_unified Threads::Threads)
# set_target_properties(test_conn_manager_outbound_limits PROPERTIES
#     RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
# add_test(NAME TestConnManagerOutboundLimits COMMAND test_conn_manager_outbound_limits)
# set_tests_properties(TestConnManagerOutboundLimits PROPERTIES TIMEOUT 30)

# Identify Push tests
add_executable(test_identify_push_reception
    tests/host/test_identify_push_reception.c)
target_link_libraries(test_identify_push_reception PRIVATE libp2p_unified)
set_target_properties(test_identify_push_reception PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME TestIdentifyPushReception COMMAND test_identify_push_reception)
set_tests_properties(TestIdentifyPushReception PROPERTIES TIMEOUT 30)

add_executable(test_identify_push_publish
    tests/host/test_identify_push_publish.c)
target_link_libraries(test_identify_push_publish PRIVATE libp2p_unified protocol_ping)
set_target_properties(test_identify_push_publish PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME TestIdentifyPushPublish COMMAND test_identify_push_publish)
set_tests_properties(TestIdentifyPushPublish PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE)

# Identify multiaddr wire-compatibility test
add_executable(test_identify_multiaddr_wire
    tests/protocol/identify/test_identify_multiaddr_wire.c)
target_link_libraries(test_identify_multiaddr_wire PRIVATE libp2p_unified)
set_target_properties(test_identify_multiaddr_wire PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME TestIdentifyMultiaddrWire COMMAND test_identify_multiaddr_wire)
set_tests_properties(TestIdentifyMultiaddrWire PROPERTIES TIMEOUT 20)

# Host server opts validation and unlisten cleanup tests
add_executable(test_host_server_opts_validation
    tests/host/test_host_server_opts_validation.c)
target_link_libraries(test_host_server_opts_validation PRIVATE libp2p_unified)
target_include_directories(test_host_server_opts_validation PRIVATE ${PROJECT_SOURCE_DIR})
set_target_properties(test_host_server_opts_validation PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME TestHostServerOptsValidation COMMAND test_host_server_opts_validation)
set_tests_properties(TestHostServerOptsValidation PROPERTIES TIMEOUT 15)

# Identify control API test
# Temporarily disable TestIdentifyControlAPI due to intermittent crash on teardown
# add_executable(test_identify_control_api
#     tests/host/test_identify_control_api.c)
# target_link_libraries(test_identify_control_api PRIVATE libp2p_unified)
# set_target_properties(test_identify_control_api PROPERTIES
#     RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
# add_test(NAME TestIdentifyControlAPI COMMAND test_identify_control_api)
# set_tests_properties(TestIdentifyControlAPI PROPERTIES TIMEOUT 20)

# Host identity API test
add_executable(test_host_identity
    tests/host/test_host_identity.c
)
target_link_libraries(test_host_identity PRIVATE libp2p_unified)
set_target_properties(test_host_identity PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME TestHostIdentity COMMAND test_host_identity)
set_tests_properties(TestHostIdentity PROPERTIES TIMEOUT 10)

# LS error event coverage tests
add_executable(test_protocol_ls_errors
    tests/host/test_protocol_ls_errors.c)
target_link_libraries(test_protocol_ls_errors PRIVATE libp2p_unified)
set_target_properties(test_protocol_ls_errors PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME TestProtocolLsErrors COMMAND test_protocol_ls_errors)
set_tests_properties(TestProtocolLsErrors PROPERTIES TIMEOUT 20)

# Note: Previously, these two tests were disabled under sanitizers due to
# flakiness on some toolchains. For debugging crashes deterministically, we
# keep them enabled so ASan can provide precise reports.

## Enable deeper event tests now that runtime integration exists
add_executable(test_host_events_listen_and_stop
    tests/host/test_host_events_listen_and_stop.c)
target_link_libraries(test_host_events_listen_and_stop PRIVATE libp2p_unified Threads::Threads)
set_target_properties(test_host_events_listen_and_stop PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME TestHostEventsListenAndStop COMMAND test_host_events_listen_and_stop)

add_executable(test_quic_upgrade_outbound
    tests/host/test_quic_upgrade_outbound.c)
target_link_libraries(test_quic_upgrade_outbound PRIVATE libp2p_unified)
target_include_directories(test_quic_upgrade_outbound PRIVATE ${PROJECT_SOURCE_DIR})
set_target_properties(test_quic_upgrade_outbound PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME TestQuicUpgradeOutbound COMMAND test_quic_upgrade_outbound)
set_tests_properties(TestQuicUpgradeOutbound PROPERTIES TIMEOUT 10)
add_executable(test_host_quic_stream_loopback
    tests/host/test_quic_stream_loopback.c)
target_link_libraries(test_host_quic_stream_loopback PRIVATE libp2p_unified)
target_include_directories(test_host_quic_stream_loopback PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR}/_deps/picotls-src/include)
set_target_properties(test_host_quic_stream_loopback PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME TestHostQuicStreamLoopback COMMAND test_host_quic_stream_loopback)
set_tests_properties(TestHostQuicStreamLoopback PROPERTIES TIMEOUT 20)

add_executable(test_quic_host_stream_exchange
    tests/host/test_quic_host_stream_exchange.c)
target_link_libraries(test_quic_host_stream_exchange PRIVATE libp2p_unified)
target_include_directories(test_quic_host_stream_exchange PRIVATE ${PROJECT_SOURCE_DIR})
set_target_properties(test_quic_host_stream_exchange PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME TestQuicHostStreamExchange COMMAND test_quic_host_stream_exchange)
set_tests_properties(TestQuicHostStreamExchange PROPERTIES TIMEOUT 20)

add_executable(test_quic_listener_accept
    tests/host/test_quic_listener_accept.c)
target_link_libraries(test_quic_listener_accept PRIVATE libp2p_unified)
target_include_directories(test_quic_listener_accept PRIVATE ${PROJECT_SOURCE_DIR})
set_target_properties(test_quic_listener_accept PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME TestQuicListenerAccept COMMAND test_quic_listener_accept)
set_tests_properties(TestQuicListenerAccept PROPERTIES TIMEOUT 20)

add_executable(test_quic_incoming_error_events
    tests/host/test_quic_incoming_error_events.c)
target_link_libraries(test_quic_incoming_error_events PRIVATE libp2p_unified)
target_include_directories(test_quic_incoming_error_events PRIVATE ${PROJECT_SOURCE_DIR})
set_target_properties(test_quic_incoming_error_events PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME TestQuicIncomingErrorEvents COMMAND test_quic_incoming_error_events)
set_tests_properties(TestQuicIncomingErrorEvents PROPERTIES TIMEOUT 10)


# dial cancellation test
add_executable(test_dial_cancellable
    tests/host/test_dial_cancellable.c)
target_link_libraries(test_dial_cancellable PRIVATE libp2p_unified)
set_target_properties(test_dial_cancellable PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME TestDialCancellable COMMAND test_dial_cancellable)
set_tests_properties(TestHostEventsListenAndStop PROPERTIES TIMEOUT 10)

# Semver scope unit test for selector helpers
add_executable(test_proto_select_semver_scope
    tests/host/test_proto_select_semver_scope.c)
target_link_libraries(test_proto_select_semver_scope PRIVATE libp2p_unified)
target_include_directories(test_proto_select_semver_scope PRIVATE ${PROJECT_SOURCE_DIR})
set_target_properties(test_proto_select_semver_scope PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME TestProtoSelectSemverScope COMMAND test_proto_select_semver_scope)
set_tests_properties(TestProtoSelectSemverScope PROPERTIES TIMEOUT 10)

# Additional semver parsing and range tests
add_executable(test_proto_select_semver_parsing
    tests/host/test_proto_select_semver_parsing.c)
target_link_libraries(test_proto_select_semver_parsing PRIVATE libp2p_unified)
target_include_directories(test_proto_select_semver_parsing PRIVATE ${PROJECT_SOURCE_DIR})
set_target_properties(test_proto_select_semver_parsing PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME TestProtoSelectSemverParsing COMMAND test_proto_select_semver_parsing)
set_tests_properties(TestProtoSelectSemverParsing PROPERTIES TIMEOUT 10)

# Temporarily keep this deeper end-to-end event test disabled; enable when
# runtime event ordering is fully deterministic across toolchains.
# add_executable(test_host_events_success_flow
#     tests/host/test_host_events_success_flow.c)
# target_link_libraries(test_host_events_success_flow PRIVATE libp2p_unified Threads::Threads)
# set_target_properties(test_host_events_success_flow PROPERTIES
#     RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
# add_test(NAME TestHostEventsSuccessFlow COMMAND test_host_events_success_flow)
# set_tests_properties(TestHostEventsSuccessFlow PROPERTIES TIMEOUT 20)

# ---------------------------------------------
# multiformats/unsigned_varint
# ---------------------------------------------
add_module(
    unsigned_varint
    src/multiformats/unsigned_varint/unsigned_varint.c
    tests/multiformats/unsigned_varint/test_unsigned_varint.c
    benchmarks/multiformats/unsigned_varint/bench_unsigned_varint.c
    src/multiformats/unsigned_varint
)

# ---------------------------------------------
# multiformats/multicodec/multicodec_table
# ---------------------------------------------
add_module(
    multicodec_table
    src/multiformats/multicodec/multicodec_table.c
    ""
    ""
    ""
)

# ---------------------------------------------
# multiformats/multicodec
# ---------------------------------------------
add_module(
    multicodec
    src/multiformats/multicodec/multicodec.c
    tests/multiformats/multicodec/test_multicodec.c
    ""
    ""
)
target_link_libraries(multicodec PUBLIC multicodec_table)

# ---------------------------------------------
# multiformats/multibase/encoding/base16
# ---------------------------------------------
add_module(
    base16
    src/multiformats/multibase/encoding/base16.c
    tests/multiformats/multibase/test_base16.c
    benchmarks/multiformats/multibase/bench_base16.c
    src/multiformats/multibase
)

# ---------------------------------------------
# multiformats/multibase/encoding/base16_upper
# ---------------------------------------------
add_module(
    base16_upper
    src/multiformats/multibase/encoding/base16_upper.c
    tests/multiformats/multibase/test_base16_upper.c
    benchmarks/multiformats/multibase/bench_base16_upper.c
    src/multiformats/multibase
)

# ---------------------------------------------
# multiformats/multibase/encoding/base32
# ---------------------------------------------
add_module(
    base32
    src/multiformats/multibase/encoding/base32.c
    tests/multiformats/multibase/test_base32.c
    ""
    ""
)

# ---------------------------------------------
# multiformats/multibase/encoding/base32_upper
# ---------------------------------------------
add_module(
    base32_upper
    src/multiformats/multibase/encoding/base32_upper.c
    tests/multiformats/multibase/test_base32_upper.c
    ""
    ""
)

# ---------------------------------------------
# multiformats/multibase/encoding/base58_btc
# ---------------------------------------------
add_module(
    base58_btc
    src/multiformats/multibase/encoding/base58_btc.c
    tests/multiformats/multibase/test_base58_btc.c
    ""
    ""
)

# ---------------------------------------------
# multiformats/multibase/encoding/base64
# ---------------------------------------------
add_module(
    base64
    src/multiformats/multibase/encoding/base64.c
    tests/multiformats/multibase/test_base64.c
    ""
    ""
)

# ---------------------------------------------
# multiformats/multibase/encoding/base64_url
# ---------------------------------------------
add_module(
    base64_url
    src/multiformats/multibase/encoding/base64_url.c
    tests/multiformats/multibase/test_base64_url.c
    ""
    ""
)

# ---------------------------------------------
# multiformats/multibase/encoding/base64_url_pad
# ---------------------------------------------
add_module(
    base64_url_pad
    src/multiformats/multibase/encoding/base64_url_pad.c
    tests/multiformats/multibase/test_base64_url_pad.c
    ""
    ""
)

# ---------------------------------------------
# multiformats/multibase/multibase
# ---------------------------------------------
add_module(
    multibase
    src/multiformats/multibase/multibase.c
    tests/multiformats/multibase/test_multibase.c
    ""
    ""
)
target_link_libraries(multibase PRIVATE
    base16 base16_upper base32 base32_upper
    base58_btc base64 base64_url base64_url_pad
)

# ---------------------------------------------
# wjcryptlib
# ---------------------------------------------
add_library(wjcryptlib
    external/wjcryptlib/lib/WjCryptLib_Sha256.c
    external/wjcryptlib/lib/WjCryptLib_Sha512.c
)
target_include_directories(wjcryptlib PUBLIC ${PROJECT_SOURCE_DIR}/external/wjcryptlib/lib)

# ---------------------------------------------
# sha3
# ---------------------------------------------
add_library(sha3
    external/sha3/sha3.c
)
target_include_directories(sha3 PUBLIC ${PROJECT_SOURCE_DIR}/external/sha3/lib)


# ---------------------------------------------
# multiformats/multihash
# ---------------------------------------------
add_module(
    multihash
    src/multiformats/multihash/multihash.c
    tests/multiformats/multihash/test_multihash.c
    ""
    ""
)
target_link_libraries(multihash PRIVATE multicodec unsigned_varint wjcryptlib sha3)

# ---------------------------------------------
# multiformats/cid_v0
# ---------------------------------------------
add_module(
    cid_v0
    src/multiformats/cid/cid_v0.c
    tests/multiformats/cid/test_cid_v0.c
    ""
    ""
)
target_link_libraries(cid_v0 PRIVATE base58_btc multicodec unsigned_varint)

# ---------------------------------------------
# multiformats/cid_v1
# ---------------------------------------------
add_module(
    cid_v1
    src/multiformats/cid/cid_v1.c
    tests/multiformats/cid/test_cid_v1.c
    ""
    ""
)
target_link_libraries(cid_v1 PRIVATE multibase multicodec unsigned_varint)

# ---------------------------------------------
# multiformats/multiaddr
# ---------------------------------------------
add_module(
    multiaddr
    src/multiformats/multiaddr/multiaddr.c
    tests/multiformats/multiaddr/test_multiaddr.c
    ""
    ""
)
target_link_libraries(multiaddr PRIVATE multibase multicodec unsigned_varint base58_btc)
if (WIN32)
  target_link_libraries(multiaddr PRIVATE ws2_32)
endif()

# ---------------------------------------------
# peer_id/peer_id_proto
# ---------------------------------------------
add_module(
    peer_id_proto
    src/peer_id/peer_id_proto.c
    ""
    ""
    src/peer_id
)
target_link_libraries(peer_id_proto PRIVATE unsigned_varint)

# ---------------------------------------------
# peer_id/peer_id_secp256k1
# ---------------------------------------------
add_module(
    peer_id_secp256k1
    src/peer_id/peer_id_secp256k1.c
    ""
    ""
    src/peer_id
)
target_link_libraries(peer_id_secp256k1 PRIVATE
    secp256k1 peer_id_proto
)
if (WIN32)
  target_link_libraries(peer_id_secp256k1 PRIVATE advapi32)
endif()

# ---------------------------------------------
# peer_id/peer_id_ed25519
# ---------------------------------------------
add_module(
    peer_id_ed25519
    src/peer_id/peer_id_ed25519.c
    ""
    ""
    src/peer_id
)
target_link_libraries(peer_id_ed25519 PRIVATE
    libtomcrypt peer_id_proto
)

# ---------------------------------------------
# peer_id/peer_id_ecdsa
# ---------------------------------------------
add_module(
    peer_id_ecdsa
    src/peer_id/peer_id_ecdsa.c
    ""
    ""
    src/peer_id
)
target_link_libraries(peer_id_ecdsa PRIVATE
    libtomcrypt peer_id_proto
)

# ---------------------------------------------
# peer_id/peer_id_rsa
# ---------------------------------------------
add_module(
    peer_id_rsa
    src/peer_id/peer_id_rsa.c
    ""
    ""
    src/peer_id
)
target_link_libraries(peer_id_rsa PRIVATE
    libtomcrypt peer_id_proto
)

# ---------------------------------------------
# peer_id
# ---------------------------------------------
add_module(
    peer_id
    src/peer_id/peer_id.c
    tests/peer_id/test_peer_id.c
    ""
    ""
)

target_link_libraries(peer_id
    PRIVATE
      peer_id_secp256k1
      peer_id_ed25519
      peer_id_ecdsa
      peer_id_rsa
      peer_id_proto
      unsigned_varint
      multibase
      multicodec
      multihash

    PUBLIC
      Threads::Threads
)

# The peer_id test can take longer on some systems due to big-number ops in RSA
set_tests_properties(Testpeer_id PROPERTIES TIMEOUT 60)

# ---------------------------------------------
# protocol/protocol_tcp
# ---------------------------------------------

add_module(
    protocol_tcp                              # MODULE_NAME  (library target)
    src/protocol/tcp/protocol_tcp.c            # MODULE_SOURCE
    tests/protocol/tcp/test_protocol_tcp.c     # TEST_SOURCE
    ""                                         # BENCH_SOURCE (none yet)
    src/protocol/tcp                           # PRIVATE_DIR  (extra includes)
)

# Link against multiaddr (which already carries all its deps) and Threads.
target_link_libraries(protocol_tcp
    PUBLIC multiaddr libp2p_metrics Threads::Threads
)

target_sources(protocol_tcp PRIVATE
    src/protocol/tcp/protocol_tcp_util.c
    src/protocol/tcp/protocol_tcp_conn.c
    src/protocol/tcp/protocol_tcp_queue.c
    src/protocol/tcp/protocol_tcp_poller.c
    src/protocol/tcp/protocol_tcp_dial.c
    src/protocol/tcp/protocol_tcp_listen.c
)


# Windows needs Winsock; *nix already linked via libc.
if (WIN32)
    target_link_libraries(protocol_tcp PRIVATE ws2_32)
endif()

# -----------------------------------------------------------------
# protocol/tcp high‑load stress test (optional)
# -----------------------------------------------------------------
if(ENABLE_STRESS_TESTS)
    add_executable(test_protocol_tcp_stress
        tests/protocol/tcp/test_protocol_tcp_stress.c
    )
    target_link_libraries(test_protocol_tcp_stress
        PRIVATE
            protocol_tcp
            Threads::Threads
    )
    set_target_properties(test_protocol_tcp_stress PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
    )

    add_test(NAME Teststress_protocol_tcp COMMAND test_protocol_tcp_stress)
    # Stress jobs can run for a while – no timeout (0 = infinite)
    set_tests_properties(Teststress_protocol_tcp PROPERTIES TIMEOUT 60)

    # On Windows, copy produced DLLs next to the test binary
    if (WIN32 AND BUILD_SHARED_LIBS)
        add_custom_command(TARGET test_protocol_tcp_stress
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
                $<TARGET_FILE_DIR:test_protocol_tcp_stress>
        )
    endif()
endif()


# ---------------------------------------------
# protocol/protocol_multiselect
# ---------------------------------------------
add_module(
    protocol_multiselect                                   # MODULE_NAME  (library)
    src/protocol/multiselect/protocol_multiselect.c        # MODULE_SOURCE
    tests/protocol/multiselect/test_protocol_multiselect.c  # TEST_SOURCE
    ""                                            # BENCH_SOURCE (none)
    src/protocol/multiselect                      # PRIVATE_DIR
)

target_link_libraries(protocol_multiselect PUBLIC unsigned_varint)

if (TARGET test_protocol_multiselect)
    target_link_libraries(test_protocol_multiselect
        PRIVATE
            protocol_tcp
            Threads::Threads
    )
    # handshake-based tests sometimes take longer than the default
    # timeout, so extend it for reliability
    set_tests_properties(Testprotocol_multiselect PROPERTIES TIMEOUT 20)
endif()

# ---------------------------------------------
# protocol/noise
# ---------------------------------------------
add_module(
    protocol_noise
    "src/protocol/noise/protocol_noise.c;src/protocol/noise/protocol_noise_conn.c;src/protocol/noise/protocol_noise_extensions.c;src/protocol/noise/protocol_noise_multiselect.c"
    tests/protocol/noise/test_protocol_noise.c
    ""
    src/protocol/noise
)

# protocol_noise depends on unsigned varint encoding/decoding helpers as part of
# the handshake payload (see src/protocol/noise/protocol_noise.c).  Without this
# link the final build fails with undefined symbol errors for
# `unsigned_varint_encode`/`unsigned_varint_decode` when creating the shared
# library.  Add the dependency explicitly so the correct archive/dylib is linked
# in.

target_link_libraries(protocol_noise PUBLIC
    libtomcrypt
    wjcryptlib
    sha3
    noiseprotocol
    protocol_multiselect
    eddsa
    peer_id_proto
    peer_id
    peer_id_ecdsa
    peer_id_rsa
    secp256k1
    unsigned_varint
)

# ---------------------------------------------
# protocol/identify
# ---------------------------------------------
add_module(
    protocol_identify
    src/protocol/identify/protocol_identify.c
    tests/protocol/identify/test_protocol_identify.c
    ""
    src/protocol/identify
)
target_link_libraries(protocol_identify PUBLIC unsigned_varint)

# Additional Identify tests
add_executable(test_protocol_identify_roundtrip
    tests/protocol/identify/test_protocol_identify_roundtrip.c)
target_link_libraries(test_protocol_identify_roundtrip PRIVATE protocol_identify)
set_target_properties(test_protocol_identify_roundtrip PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME Testprotocol_identify_roundtrip COMMAND test_protocol_identify_roundtrip)
set_tests_properties(Testprotocol_identify_roundtrip PROPERTIES TIMEOUT 10)

## Removed legacy protocol_handler module; unified API supersedes it

# ---------------------------------------------
# protocol/ping
# ---------------------------------------------
add_module(
    protocol_ping
    src/protocol/ping/protocol_ping.c
    tests/protocol/ping/test_protocol_ping.c
    ""
    src/protocol/ping
)
target_link_libraries(protocol_ping PUBLIC libp2p_unified)

# ---------------------------------------------
# protocol/gossipsub
# ---------------------------------------------
add_module(
    protocol_gossipsub
    "src/protocol/gossipsub/core/gossipsub_service.c;src/protocol/gossipsub/core/gossipsub_cache.c;src/protocol/gossipsub/core/gossipsub_peer.c;src/protocol/gossipsub/core/gossipsub_internal.c;src/protocol/gossipsub/core/gossipsub_topic.c;src/protocol/gossipsub/core/gossipsub_validation.c;src/protocol/gossipsub/core/gossipsub_rpc.c;src/protocol/gossipsub/core/gossipsub_propagation.c;src/protocol/gossipsub/core/gossipsub_heartbeat.c;src/protocol/gossipsub/core/gossipsub_host_events.c;src/protocol/gossipsub/core/gossipsub_score.c;src/protocol/gossipsub/core/gossipsub_promises.c"
    "tests/protocol/gossipsub/test_gossipsub_service.c;tests/protocol/gossipsub/test_gossipsub_service_common.c;tests/protocol/gossipsub/test_gossipsub_service_setup.c;tests/protocol/gossipsub/test_gossipsub_service_subscription_mesh.c;tests/protocol/gossipsub/test_gossipsub_service_heartbeat.c;tests/protocol/gossipsub/test_gossipsub_service_px.c;tests/protocol/gossipsub/test_gossipsub_service_scoring.c;tests/protocol/gossipsub/test_gossipsub_service_explicit.c;tests/protocol/gossipsub/test_gossipsub_service_cleanup.c"
    ""
    src/protocol/gossipsub/core
)
add_dependencies(protocol_gossipsub gossipsub_proto)
target_sources(protocol_gossipsub PRIVATE
    src/protocol/gossipsub/proto/gossipsub_proto.c
    ${GOSSIPSUB_PROTO_C}
)
target_include_directories(protocol_gossipsub PRIVATE
    ${PROJECT_SOURCE_DIR}/src/protocol/gossipsub/proto
    ${GOSSIPSUB_PROTO_GEN_DIR}
)
target_link_libraries(protocol_gossipsub
    PUBLIC libp2p_unified
    PRIVATE noiseprotocol noiseprotobufs
)
set_tests_properties(Testprotocol_gossipsub PROPERTIES TIMEOUT 30)

add_executable(test_gossipsub_proto
    tests/protocol/gossipsub/test_gossipsub_proto.c
)
target_link_libraries(test_gossipsub_proto PRIVATE protocol_gossipsub)
set_target_properties(test_gossipsub_proto PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
target_include_directories(test_gossipsub_proto PRIVATE
    ${PROJECT_SOURCE_DIR}/src/protocol/gossipsub/proto
    ${GOSSIPSUB_PROTO_GEN_DIR}
)
add_test(NAME Testgossipsub_proto COMMAND test_gossipsub_proto)
set_tests_properties(Testgossipsub_proto PROPERTIES TIMEOUT 10)

add_executable(test_gossipsub_cache
    tests/protocol/gossipsub/test_gossipsub_cache.c
)
target_link_libraries(test_gossipsub_cache PRIVATE protocol_gossipsub)
target_include_directories(test_gossipsub_cache PRIVATE
    ${PROJECT_SOURCE_DIR}/src/protocol/gossipsub/core
)
set_target_properties(test_gossipsub_cache PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME Testgossipsub_cache COMMAND test_gossipsub_cache)
set_tests_properties(Testgossipsub_cache PROPERTIES TIMEOUT 10)

add_executable(test_gossipsub_validation
    tests/protocol/gossipsub/test_gossipsub_validation.c
)
target_link_libraries(test_gossipsub_validation PRIVATE protocol_gossipsub)
target_include_directories(test_gossipsub_validation PRIVATE
    ${PROJECT_SOURCE_DIR}/src/protocol/gossipsub/core
    ${PROJECT_SOURCE_DIR}/src/protocol/gossipsub/proto
    ${GOSSIPSUB_PROTO_GEN_DIR}
)
set_target_properties(test_gossipsub_validation PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME Testgossipsub_validation COMMAND test_gossipsub_validation)
set_tests_properties(Testgossipsub_validation PROPERTIES TIMEOUT 10)

# ---------------------------------------------
# protocol/quic (skeleton)
# ---------------------------------------------
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
add_library(protocol_quic STATIC
    src/protocol/quic/protocol_quic.c
    src/protocol/quic/quic_listener.c
    src/protocol/quic/quic_conn.c
    src/protocol/quic/quic_tls.c
    src/protocol/quic/quic_muxer.c
)
set_target_properties(protocol_quic PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(protocol_quic PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_include_directories(protocol_quic PRIVATE ${PROJECT_SOURCE_DIR}/src/protocol/quic)
target_include_directories(protocol_quic PRIVATE ${PROJECT_BINARY_DIR}/_deps/picotls-src/include)
if(ENABLE_CLANG_TIDY AND LIBP2P_CLANG_TIDY)
    set_target_properties(protocol_quic PROPERTIES C_CLANG_TIDY "${LIBP2P_CLANG_TIDY}")
endif()
target_link_libraries(protocol_quic
    PRIVATE
        multiaddr
        libtomcrypt
        wjcryptlib
        eddsa
        secp256k1
    PUBLIC
        peer_id
        peer_id_proto
        OpenSSL::Crypto
)
# Link to vendor interface (picoquic-core) if available; safe even unused
if(TARGET libp2p_quic_vendor)
    target_link_libraries(protocol_quic PUBLIC libp2p_quic_vendor)
endif()
# libp2p_unified calls the QUIC factory; ensure symbol availability
target_link_libraries(libp2p_unified PUBLIC protocol_quic)

add_executable(test_protocol_quic tests/protocol/quic/test_quic_tls_identity.c)
target_link_libraries(test_protocol_quic PRIVATE protocol_quic peer_id)
set_target_properties(test_protocol_quic PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME Testprotocol_quic COMMAND test_protocol_quic)
set_tests_properties(Testprotocol_quic PROPERTIES TIMEOUT 10)

add_executable(test_quic_can_handle tests/protocol/quic/test_quic_can_handle.c)
target_link_libraries(test_quic_can_handle PRIVATE libp2p_unified)
set_target_properties(test_quic_can_handle PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME Testquic_can_handle COMMAND test_quic_can_handle)
set_tests_properties(Testquic_can_handle PROPERTIES TIMEOUT 5)

add_executable(test_quic_listener_lifecycle tests/protocol/quic/test_quic_listener_lifecycle.c)
target_link_libraries(test_quic_listener_lifecycle PRIVATE libp2p_unified)
set_target_properties(test_quic_listener_lifecycle PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME Testquic_listener_lifecycle COMMAND test_quic_listener_lifecycle)
set_tests_properties(Testquic_listener_lifecycle PROPERTIES TIMEOUT 20)

add_executable(test_quic_tls_certificate tests/protocol/quic/test_quic_tls_certificate.c)
target_link_libraries(test_quic_tls_certificate PRIVATE protocol_quic)
set_target_properties(test_quic_tls_certificate PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME Testquic_tls_certificate COMMAND test_quic_tls_certificate)
set_tests_properties(Testquic_tls_certificate PROPERTIES TIMEOUT 10)

add_executable(test_quic_stream_loopback tests/protocol/quic/test_quic_stream_loopback.c)
target_link_libraries(test_quic_stream_loopback PRIVATE libp2p_unified)
target_include_directories(test_quic_stream_loopback PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR}/_deps/picotls-src/include)
set_target_properties(test_quic_stream_loopback PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME Testquic_stream_loopback COMMAND test_quic_stream_loopback)
set_tests_properties(Testquic_stream_loopback PROPERTIES TIMEOUT 20)
# ---------------------------------------------
# protocol/muxer/mplex
# ---------------------------------------------
add_module(
    protocol_mplex
    "src/protocol/muxer/mplex/protocol_mplex_ctx.c;src/protocol/muxer/mplex/protocol_mplex_conn.c;src/protocol/muxer/mplex/protocol_mplex_stream.c;src/protocol/muxer/mplex/protocol_mplex_util.c;src/protocol/muxer/mplex/protocol_mplex_process.c;src/protocol/muxer/mplex/protocol_mplex_write_queue.c;src/protocol/muxer/mplex/protocol_mplex_send.c;src/protocol/muxer/mplex/protocol_mplex_event.c;src/protocol/muxer/mplex/protocol_mplex_event_loop.c"
    ""
    ""
    src/protocol/muxer/mplex
)
target_link_libraries(protocol_mplex
    PUBLIC
        protocol_multiselect
        unsigned_varint
        Threads::Threads
        protocol_tcp
)

if (TARGET test_protocol_mplex)
    target_link_libraries(test_protocol_mplex
        PRIVATE
            protocol_tcp
            Threads::Threads
    )
    # negotiation and frame roundtrip may take slightly longer on
    # slower systems, so allow a bit more time
    set_tests_properties(Testprotocol_mplex PROPERTIES TIMEOUT 20)
endif()

# ---------------------------------------------
# protocol/muxer/mplex 
# ---------------------------------------------
add_executable(test_mplex_basic
    tests/protocol/muxer/mplex/test_mplex_basic.c
)
target_link_libraries(test_mplex_basic PRIVATE 
    protocol_mplex
    Threads::Threads
)
set_target_properties(test_mplex_basic PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME TestMplexBasic COMMAND test_mplex_basic)
set_tests_properties(TestMplexBasic PROPERTIES TIMEOUT 20)

add_executable(test_mplex_backpressure
    tests/protocol/muxer/mplex/test_mplex_backpressure.c
)
target_include_directories(test_mplex_backpressure PRIVATE ${PROJECT_SOURCE_DIR}/external/noise-c/include)
target_link_libraries(test_mplex_backpressure PRIVATE
    protocol_mplex
    protocol_tcp
    protocol_noise
    noiseprotocol
    Threads::Threads
)
set_target_properties(test_mplex_backpressure PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME TestMplexBackpressure COMMAND test_mplex_backpressure)
set_tests_properties(TestMplexBackpressure PROPERTIES TIMEOUT 60)

add_executable(test_mplex_edge_cases
    tests/protocol/muxer/mplex/test_mplex_edge_cases.c
)
target_link_libraries(test_mplex_edge_cases PRIVATE 
    protocol_mplex
    Threads::Threads
)
set_target_properties(test_mplex_edge_cases PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME TestMplexEdgeCases COMMAND test_mplex_edge_cases)
set_tests_properties(TestMplexEdgeCases PROPERTIES TIMEOUT 30)

add_executable(test_mplex_event_driven_streams
    tests/protocol/muxer/mplex/test_mplex_event_driven_streams.c
)
target_link_libraries(test_mplex_event_driven_streams PRIVATE 
    protocol_mplex
    Threads::Threads
)
set_target_properties(test_mplex_event_driven_streams PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME TestMplexEventDrivenStreams COMMAND test_mplex_event_driven_streams)
set_tests_properties(TestMplexEventDrivenStreams PROPERTIES TIMEOUT 60)

add_executable(test_mplex_message_types
    tests/protocol/muxer/mplex/test_mplex_message_types.c
)
target_link_libraries(test_mplex_message_types PRIVATE
    protocol_mplex
    protocol_tcp
    protocol_noise
    noiseprotocol
    Threads::Threads
)
set_target_properties(test_mplex_message_types PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME TestMplexMessageTypes COMMAND test_mplex_message_types)
set_tests_properties(TestMplexMessageTypes PROPERTIES TIMEOUT 60)

add_executable(test_mplex_real_connection
    tests/protocol/muxer/mplex/test_mplex_real_connection.c
)
target_link_libraries(test_mplex_real_connection PRIVATE
    protocol_mplex
    protocol_tcp
    protocol_noise
    noiseprotocol
    Threads::Threads
)
set_target_properties(test_mplex_real_connection PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME TestMplexRealConnection COMMAND test_mplex_real_connection)
set_tests_properties(TestMplexRealConnection PROPERTIES TIMEOUT 60)

add_executable(test_mplex_protocol_edge_cases
    tests/protocol/muxer/mplex/test_mplex_protocol_edge_cases.c
)
target_link_libraries(test_mplex_protocol_edge_cases PRIVATE
    protocol_mplex
    unsigned_varint
    Threads::Threads
)
set_target_properties(test_mplex_protocol_edge_cases PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME TestMplexProtocolEdgeCases COMMAND test_mplex_protocol_edge_cases)
set_tests_properties(TestMplexProtocolEdgeCases PROPERTIES TIMEOUT 30)

# On Windows, copy produced DLLs next to the test binaries
if (WIN32 AND BUILD_SHARED_LIBS)
    add_custom_command(TARGET test_mplex_basic
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
            $<TARGET_FILE_DIR:test_mplex_basic>
    )
    
    add_custom_command(TARGET test_mplex_edge_cases
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
            $<TARGET_FILE_DIR:test_mplex_edge_cases>
    )
    add_custom_command(TARGET test_mplex_event_driven_streams
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
            $<TARGET_FILE_DIR:test_mplex_event_driven_streams>
    )
endif()

# ---------------------------------------------
# protocol/muxer/yamux
# ---------------------------------------------
add_module(
    protocol_yamux
    "src/protocol/muxer/yamux/protocol_yamux.c;src/protocol/muxer/yamux/protocol_yamux_queue.c;src/protocol/muxer/yamux/yamux_io_adapter.c"
    tests/protocol/muxer/yamux/test_protocol_yamux.c
    ""
    src/protocol/muxer/yamux
)
target_link_libraries(protocol_yamux
    PUBLIC
        protocol_multiselect
        protocol_tcp
)

target_sources(protocol_yamux PRIVATE src/transport/conn_util.c)
# Windows needs Winsock for network byte order functions
if (WIN32)
    target_link_libraries(protocol_yamux PRIVATE ws2_32)
endif()

if (TARGET test_protocol_yamux)
    target_link_libraries(test_protocol_yamux
        PRIVATE
            protocol_tcp
            Threads::Threads
    )
    set_tests_properties(Testprotocol_yamux PROPERTIES TIMEOUT 60)
endif()

# Yamux substream -> libp2p_stream end-to-end
add_executable(test_yamux_substream_stream
    tests/protocol/muxer/yamux/test_yamux_substream_stream.c
)
target_link_libraries(test_yamux_substream_stream PRIVATE libp2p_unified Threads::Threads)
set_target_properties(test_yamux_substream_stream PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME TestYamuxSubstreamStream COMMAND test_yamux_substream_stream)
set_tests_properties(TestYamuxSubstreamStream PROPERTIES TIMEOUT 60)

if (TARGET test_protocol_noise)
    target_link_libraries(test_protocol_noise
        PRIVATE
            protocol_tcp
            protocol_mplex
            multiaddr
            secp256k1
            unsigned_varint
            eddsa
            peer_id_ed25519
            peer_id_ecdsa
            peer_id_rsa
            Threads::Threads
    )
    # Provide access to eddsa public headers for the test source
    target_include_directories(test_protocol_noise PRIVATE ${PROJECT_SOURCE_DIR}/external/libeddsa/lib)

    # Noise handshake test suite can take a while on Windows CI – allow 60 s.
    set_tests_properties(Testprotocol_noise PROPERTIES TIMEOUT 60)
endif()

# ---------------------------------------------
# transport/upgrader
# ---------------------------------------------
add_module(
    transport_upgrader
    src/transport/upgrader.c
    tests/transport/test_upgrader.c
    ""
    src/transport
)

target_link_libraries(transport_upgrader PUBLIC protocol_noise protocol_mplex)

if (TARGET test_transport_upgrader)
    target_link_libraries(test_transport_upgrader
        PRIVATE
            protocol_tcp
            multiaddr
            eddsa
            peer_id
            peer_id_ed25519
            Threads::Threads
    )
    target_include_directories(test_transport_upgrader PRIVATE ${PROJECT_SOURCE_DIR}/external/libeddsa/lib)
endif()
