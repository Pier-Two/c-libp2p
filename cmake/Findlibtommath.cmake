# Findlibtommath.cmake
# Custom find module for libtommath

# Check if libtommath is already a target
if(TARGET libtommath)
    set(libtommath_FOUND TRUE)
    set(libtommath_LIBRARIES libtommath)
    get_target_property(libtommath_INCLUDE_DIRS libtommath INTERFACE_INCLUDE_DIRECTORIES)
    if(NOT libtommath_INCLUDE_DIRS)
        set(libtommath_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/external/libtommath)
    endif()
    return()
endif()

# Find the headers
find_path(libtommath_INCLUDE_DIR tommath.h
    PATHS ${CMAKE_SOURCE_DIR}/external/libtommath
    NO_DEFAULT_PATH
)

# Find the library
find_library(libtommath_LIBRARY
    NAMES tommath libtommath
    PATHS
        ${CMAKE_BINARY_DIR}/external/libtommath
        ${CMAKE_BINARY_DIR}/lib
    NO_DEFAULT_PATH
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libtommath DEFAULT_MSG libtommath_LIBRARY libtommath_INCLUDE_DIR)

if(libtommath_FOUND)
    set(libtommath_LIBRARIES ${libtommath_LIBRARY})
    set(libtommath_INCLUDE_DIRS ${libtommath_INCLUDE_DIR})
endif()

mark_as_advanced(libtommath_INCLUDE_DIR libtommath_LIBRARY)
