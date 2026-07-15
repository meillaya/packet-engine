cmake_minimum_required(VERSION 3.25)

# Pin the generator to Ninja for fast incremental builds and clean
# compile_commands.json generation.
set(CMAKE_GENERATOR "Ninja" CACHE INTERNAL "")

project(packet-engine
  VERSION 0.1.0
  DESCRIPTION "C++23 high-performance packet engine"
  LANGUAGES CXX
)

if(POLICY CMP0167)
  # Use Boost's upstream CMake config instead of the deprecated FindBoost module.
  cmake_policy(SET CMP0167 NEW)
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(BUILD_TESTING ON CACHE BOOL "Build tests" FORCE)

include(CTest)
include(FindPkgConfig)

# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------
option(ENABLE_DPDK "Enable DPDK datapath support" OFF)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)

# -----------------------------------------------------------------------------
# Compiler warnings
# -----------------------------------------------------------------------------
add_library(pe_warnings INTERFACE)
target_compile_options(pe_warnings INTERFACE
  -Wall
  -Wextra
  -Wpedantic
  -Werror
)

# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------
find_package(Threads REQUIRED)

# Boost.Lockfree is header-only; request the headers target rather than a
# compiled component that may not ship a CMake config file.
find_package(Boost REQUIRED)

pkg_check_modules(LIBXDP REQUIRED libxdp)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(NLOHMANN_JSON REQUIRED nlohmann_json)

# libnuma is optional -- the FrameAllocator falls back to plain mmap
# when NUMACTL is missing, and the test suite skips the NUMA assertions.
pkg_check_modules(NUMACTL numa)

if(ENABLE_DPDK)
  pkg_check_modules(DPDK REQUIRED libdpdk)
endif()

# libbpf depends on libelf from the nixpkgs elfutils package.  pkg-config for
# libbpf in the nix shell does not expose the elfutils -L path, and the nix
# store versions of libbpf/libxdp must be preferred over the host /usr/lib
# copies at runtime.  Embed the relevant nix store lib directories in every
# executable's rpath.
set(ELFUTILS_LIB_DIR "/nix/store/6nrfjqgkbgwjrszrn9dfv5k7kj7vxxfk-elfutils-0.194/lib")
list(APPEND CMAKE_BUILD_RPATH
  ${LIBBPF_LIBRARY_DIRS}
  ${LIBXDP_LIBRARY_DIRS}
  "${ELFUTILS_LIB_DIR}"
)
list(APPEND CMAKE_INSTALL_RPATH
  ${LIBBPF_LIBRARY_DIRS}
  ${LIBXDP_LIBRARY_DIRS}
  "${ELFUTILS_LIB_DIR}"
)

# -----------------------------------------------------------------------------
# Sanitizer options
# -----------------------------------------------------------------------------
if(ENABLE_ASAN OR ENABLE_UBSAN)
  add_library(pe_sanitizer INTERFACE)
  target_compile_options(pe_sanitizer INTERFACE -fno-omit-frame-pointer)

  if(ENABLE_ASAN)
    target_compile_options(pe_sanitizer INTERFACE -fsanitize=address)
    target_link_options(pe_sanitizer INTERFACE -fsanitize=address)
  endif()

  if(ENABLE_UBSAN)
    target_compile_options(pe_sanitizer INTERFACE -fsanitize=undefined)
    target_link_options(pe_sanitizer INTERFACE -fsanitize=undefined)
  endif()
endif()

# Build the XDP program as part of the normal build.  The BPF subdirectory
# writes only below the active build tree, so parallel build directories do
# not race over a source-tree object.
add_subdirectory(bpf)

# -----------------------------------------------------------------------------
# Core static library
# -----------------------------------------------------------------------------
add_library(packet_engine_core STATIC)
add_dependencies(packet_engine_core af_xdp_kern)
target_sources(packet_engine_core PRIVATE
  src/backend_af_xdp.cpp
  src/engine_config.cpp
  src/frame_allocator.cpp
  src/numa_topology.cpp
  src/worker_pool.cpp
  src/parser.cpp
  src/packet_processor.cpp
  src/metrics_aggregator.cpp
  src/bpf_loader.cpp
  src/datapath_loop.cpp
  src/rule_hash.cpp
  src/rule_schema.cpp
  src/token_bucket.cpp
  src/cidr_trie.cpp
  src/rule_table.cpp
  src/md5.cpp
  src/ketama.cpp
  src/backend_registry.cpp
  src/control_api.cpp
  src/conntrack.cpp
  src/health_prober.cpp
  src/nat.cpp
  src/metrics_endpoint.cpp
)

if(ENABLE_DPDK)
  target_sources(packet_engine_core PRIVATE src/backend_dpdk.cpp)
endif()

target_include_directories(packet_engine_core
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  SYSTEM PUBLIC
    ${NLOHMANN_JSON_INCLUDE_DIRS}
)

target_link_libraries(packet_engine_core
  PUBLIC
    Threads::Threads
    Boost::headers
    pe_warnings
    ${NLOHMANN_JSON_LIBRARIES}
)

target_compile_options(packet_engine_core PUBLIC ${NLOHMANN_JSON_CFLAGS_OTHER})
target_compile_definitions(packet_engine_core PRIVATE
  PACKET_ENGINE_BPF_OBJECT_PATH="${CMAKE_CURRENT_BINARY_DIR}/bpf/af_xdp_kern.o"
)

if(ENABLE_ASAN OR ENABLE_UBSAN)
  target_link_libraries(packet_engine_core PUBLIC pe_sanitizer)
endif()

# XDP / BPF are compile-time dependencies for the core engine.
target_include_directories(packet_engine_core SYSTEM PUBLIC ${LIBXDP_INCLUDE_DIRS} ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(packet_engine_core PUBLIC ${LIBXDP_LIBRARIES} ${LIBBPF_LIBRARIES})
target_compile_options(packet_engine_core PUBLIC ${LIBXDP_CFLAGS_OTHER} ${LIBBPF_CFLAGS_OTHER})

# libnuma (NUMA bind) is plumbed into the core library when available.
if(NUMACTL_FOUND)
  target_include_directories(packet_engine_core SYSTEM PUBLIC ${NUMACTL_INCLUDE_DIRS})
  target_link_libraries(packet_engine_core PUBLIC ${NUMACTL_LIBRARIES})
  target_compile_definitions(packet_engine_core PUBLIC HAVE_NUMACTL=1)
endif()

if(ENABLE_DPDK)
  target_compile_definitions(packet_engine_core PUBLIC HAVE_DPDK)
  target_include_directories(packet_engine_core SYSTEM PUBLIC ${DPDK_INCLUDE_DIRS})
  target_link_libraries(packet_engine_core PUBLIC ${DPDK_LIBRARIES})
  target_compile_options(packet_engine_core PUBLIC ${DPDK_CFLAGS_OTHER})
endif()

# -----------------------------------------------------------------------------
# Prometheus support library (header-only)
# -----------------------------------------------------------------------------
add_library(packet_engine_prometheus INTERFACE)
target_include_directories(packet_engine_prometheus
  INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(packet_engine_prometheus INTERFACE Threads::Threads)

# -----------------------------------------------------------------------------
# Executables
# -----------------------------------------------------------------------------
add_executable(packet-engine)
target_sources(packet-engine PRIVATE src/main.cpp src/runtime_context.cpp)
target_link_libraries(packet-engine PRIVATE packet_engine_core)
add_dependencies(packet-engine af_xdp_kern)
set_target_properties(packet-engine PROPERTIES
  BUILD_RPATH "${LIBBPF_LIBRARY_DIRS};${LIBXDP_LIBRARY_DIRS};${ELFUTILS_LIB_DIR}"
  INSTALL_RPATH "${LIBBPF_LIBRARY_DIRS};${LIBXDP_LIBRARY_DIRS};${ELFUTILS_LIB_DIR}"
)

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
if(BUILD_TESTING)
  find_package(GTest REQUIRED)
  add_subdirectory(tests)
endif()

# -----------------------------------------------------------------------------
# Quality targets
# -----------------------------------------------------------------------------
find_program(CLANG_TIDY_EXE clang-tidy)
if(CLANG_TIDY_EXE)
  get_target_property(PACKET_ENGINE_CORE_SOURCES packet_engine_core SOURCES)
  set(PACKET_ENGINE_TIDY_SOURCES)
  foreach(source_file IN LISTS PACKET_ENGINE_CORE_SOURCES)
    if(IS_ABSOLUTE "${source_file}")
      list(APPEND PACKET_ENGINE_TIDY_SOURCES "${source_file}")
    else()
      list(APPEND PACKET_ENGINE_TIDY_SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/${source_file}"
      )
    endif()
  endforeach()
  list(APPEND PACKET_ENGINE_TIDY_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/runtime_context.cpp"
  )

  add_custom_target(clang-tidy
    COMMAND ${CLANG_TIDY_EXE} -p ${CMAKE_BINARY_DIR}
            --warnings-as-errors=*
            ${PACKET_ENGINE_TIDY_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Running clang-tidy"
    VERBATIM
    COMMAND_EXPAND_LISTS
  )
else()
  add_custom_target(clang-tidy
    COMMAND ${CMAKE_COMMAND} -E echo
            "clang-tidy unavailable: configure inside the project development shell"
    COMMAND ${CMAKE_COMMAND} -E false
    COMMENT "clang-tidy unavailable"
    VERBATIM
  )
endif()

find_program(CLANG_FORMAT_EXE clang-format)
if(CLANG_FORMAT_EXE)
  file(GLOB_RECURSE ALL_SOURCE_FILES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/packet-engine/*.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf/*.c
  )
  add_custom_target(format-check
    COMMAND ${CLANG_FORMAT_EXE} --dry-run -Werror ${ALL_SOURCE_FILES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Checking formatting"
    VERBATIM
    COMMAND_EXPAND_LISTS
  )
  add_custom_target(format
    COMMAND ${CLANG_FORMAT_EXE} -i ${ALL_SOURCE_FILES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Formatting sources in place"
    VERBATIM
    COMMAND_EXPAND_LISTS
  )
else()
  add_custom_target(format-check
    COMMAND ${CMAKE_COMMAND} -E echo
            "clang-format unavailable: configure inside the project development shell"
    COMMAND ${CMAKE_COMMAND} -E false
    COMMENT "clang-format unavailable"
    VERBATIM
  )
  add_custom_target(format
    COMMAND ${CMAKE_COMMAND} -E echo
            "clang-format unavailable: configure inside the project development shell"
    COMMAND ${CMAKE_COMMAND} -E false
    COMMENT "clang-format unavailable"
    VERBATIM
  )
endif()

find_program(SHELLCHECK_EXE shellcheck)
file(GLOB PACKET_ENGINE_SHELL_SOURCES CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/scripts/*.sh
  ${CMAKE_CURRENT_SOURCE_DIR}/bench/*.sh
)
if(SHELLCHECK_EXE)
  add_custom_target(shellcheck
    COMMAND ${SHELLCHECK_EXE} ${PACKET_ENGINE_SHELL_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Running shellcheck"
    VERBATIM
    COMMAND_EXPAND_LISTS
  )
else()
  add_custom_target(shellcheck
    COMMAND ${CMAKE_COMMAND} -E echo
            "shellcheck unavailable: install it or use the project development shell"
    COMMAND ${CMAKE_COMMAND} -E false
    COMMENT "shellcheck unavailable"
    VERBATIM
  )
endif()

# The aggregate lint target is intentionally strict: diagnostics from either
# static C++ analysis or shell analysis fail the target.
add_custom_target(lint)
add_dependencies(lint clang-tidy shellcheck)
