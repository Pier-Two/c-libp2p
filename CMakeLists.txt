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
  if("${CMAKE_OSX_ARCHITECTURES}" STREQUAL "")
    set(CMAKE_OSX_ARCHITECTURES "${CMAKE_SYSTEM_PROCESSOR}" CACHE STRING "Build architectures for macOS" FORCE)
    message(STATUS "Building for macOS architecture: ${CMAKE_OSX_ARCHITECTURES}")
  endif()
endif()

option(ENABLE_SANITIZERS "Enable Address, UndefinedBehavior, Thread, etc. Sanitizers" OFF)
set(SANITIZERS "address;undefined" CACHE STRING "List of sanitizers to enable (semicolon-separated)")

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
_add_subdirectory_no_tests(lib/secp256k1)

# Add libtommath submodule.
#
# On macOS with Apple Clang 17, linking libtommath as a shared library has been
# observed to crash the system linker (Segmentation fault: 11) on some setups.
# To avoid this toolchain issue, force libtommath to build as a static library
# and ensure it is position‑independent so it can be linked into shared libs.
set(_saved_BUILD_SHARED_LIBS "${BUILD_SHARED_LIBS}")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build using shared libraries" FORCE)
_add_subdirectory_no_tests(lib/libtommath)
set(BUILD_SHARED_LIBS "${_saved_BUILD_SHARED_LIBS}" CACHE BOOL "Build using shared libraries" FORCE)
set(libtommath_DIR "${CMAKE_BINARY_DIR}/lib/libtommath")

# Workarounds for libtommath build under our global -O0/-g settings.
if(TARGET libtommath)
  # Ensure codegen keeps dead‑code elimination needed by MP_HAS(...)
  target_compile_options(libtommath PRIVATE -O1 -g)
  # Allow static lib to link into shared libraries cleanly
  set_target_properties(libtommath PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

# Add libtomcrypt submodule.
_add_subdirectory_no_tests(lib/libtomcrypt)
target_compile_definitions(libtomcrypt PRIVATE USE_LTM LTM_DESC)

# Add noise-c submodule with crypto backends disabled.
set(USE_LIBSODIUM OFF CACHE BOOL "" FORCE)
set(USE_OPENSSL OFF CACHE BOOL "" FORCE)
_add_subdirectory_no_tests(lib/noise-c)
set_target_properties(noiseprotocol PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_sources(noiseprotocol PRIVATE ${CMAKE_SOURCE_DIR}/cmake/newhope_abs_shim.c)

# ---------------------------------------------------------------------------
# Workaround: MinGW/Windows build failure in Noise-C's NewHope implementation
# ---------------------------------------------------------------------------
# The file `error_correction.c` inside the Noise-C submodule defines a local
#   static int32_t abs(int32_t v)
# which collides with the standard C `abs()` declared in <math.h> on Windows
# (and pulled in indirectly by system headers).  We cannot patch the submodule
# in-place, so instead rename the local symbol *only for that translation
# unit*.  Using a per-source compile definition avoids side-effects elsewhere.

if (TARGET noiseprotocol)
    # Inject helper header globally (provides macro + inline impl)
    target_compile_options(noiseprotocol PRIVATE
        "-include${CMAKE_SOURCE_DIR}/cmake/noise_newhope_abs_fix.h")

    # Rename curve25519-donna helper fmul() to avoid libc conflict
    target_compile_options(noiseprotocol PRIVATE
        "-include${CMAKE_SOURCE_DIR}/cmake/noise_fmul_fix.h")

    # For the original NewHope source file, keep the macro but suppress the
    # inline implementation to avoid duplicate definitions.
    set_source_files_properties(
        ${PROJECT_SOURCE_DIR}/lib/noise-c/src/crypto/newhope/error_correction.c
        PROPERTIES
            COMPILE_DEFINITIONS "NEWHOPE_ABS_NO_IMPL"
    )
endif()

# Add libeddsa submodule.
_add_subdirectory_no_tests(lib/libeddsa)

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
    src/host/host_upgrader_helpers.c
    src/host/host_events.c
    
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
    src/util/log.c
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
    lib/wjcryptlib/lib/WjCryptLib_Sha256.c
    lib/wjcryptlib/lib/WjCryptLib_Sha512.c
)
target_include_directories(wjcryptlib PUBLIC ${PROJECT_SOURCE_DIR}/lib/wjcryptlib/lib)

# ---------------------------------------------
# sha3
# ---------------------------------------------
add_library(sha3
    lib/sha3/sha3.c
)
target_include_directories(sha3 PUBLIC ${PROJECT_SOURCE_DIR}/lib/sha3/lib)


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
target_include_directories(test_mplex_backpressure PRIVATE ${PROJECT_SOURCE_DIR}/lib/noise-c/include)
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
    target_include_directories(test_protocol_noise PRIVATE ${PROJECT_SOURCE_DIR}/lib/libeddsa/lib)

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
    target_include_directories(test_transport_upgrader PRIVATE ${PROJECT_SOURCE_DIR}/lib/libeddsa/lib)
endif()
