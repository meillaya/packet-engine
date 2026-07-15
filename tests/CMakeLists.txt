enable_testing()
include(GoogleTest)

# -----------------------------------------------------------------------------
# Concurrently-written tests directory: each implementation task may add a
# `test_<feature>.cpp` at any time.  We glob the directory and create one
# GoogleTest executable per source file so a single broken test never blocks
# the rest, and any new test is picked up on the next configure pass.
# -----------------------------------------------------------------------------

file(GLOB PACKET_ENGINE_TEST_SOURCES "test_*.cpp")
file(GLOB PACKET_ENGINE_BENCH_SOURCES "bench_*.cpp")

# Tests that don't need the core library.
set(PACKET_ENGINE_NO_CORE_TESTS
    test_prometheus_client.cpp
)

# Tests that only build when DPDK is enabled.  Without ENABLE_DPDK=ON,
# `src/backend_dpdk.cpp` is omitted from `packet_engine_core` and the
# DpdkBackend class symbols are unavailable, so these tests must be
# skipped to keep the test target linkable in the default build.
set(PACKET_ENGINE_DPDK_ONLY_TESTS
    test_dpdk_link.cpp
)

set(PACKET_ENGINE_NO_PROM_TESTS
)

foreach(test_src ${PACKET_ENGINE_TEST_SOURCES})
  if(NOT IS_ABSOLUTE "${test_src}")
    set(test_src "${CMAKE_CURRENT_SOURCE_DIR}/${test_src}")
  endif()

  get_filename_component(test_we "${test_src}" NAME_WE)
  get_filename_component(test_file "${test_src}" NAME)

  # Skip DPDK-only tests when the optional backend is disabled.  These
  # tests reference `DpdkBackend` symbols from `src/backend_dpdk.cpp`,
  # which is itself excluded from the core library when ENABLE_DPDK=OFF.
  if("${test_file}" IN_LIST PACKET_ENGINE_DPDK_ONLY_TESTS AND NOT ENABLE_DPDK)
    continue()
  endif()

  add_executable("${test_we}" "${test_src}")
  target_link_libraries("${test_we}" PRIVATE GTest::gtest_main)

  # Make the in-tree `mocks/` headers (e.g. `mocks/mock_xsk.h`) reachable
  # for every test, harmless for tests that don't use them.
  target_include_directories("${test_we}" PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

  if(NOT "${test_file}" IN_LIST PACKET_ENGINE_NO_CORE_TESTS
     AND TARGET packet_engine_core)
    target_link_libraries("${test_we}" PRIVATE packet_engine_core)
  endif()

  if(TARGET packet_engine_prometheus)
    target_link_libraries("${test_we}" PRIVATE packet_engine_prometheus)
  endif()

  if(NUMACTL_FOUND)
    target_include_directories("${test_we}" SYSTEM PRIVATE ${NUMACTL_INCLUDE_DIRS})
    target_link_libraries("${test_we}" PRIVATE ${NUMACTL_LIBRARIES})
    target_compile_definitions("${test_we}" PRIVATE HAVE_NUMACTL=1)
  endif()

  # Propagate `HAVE_DPDK` from the parent directory's `if(ENABLE_DPDK)`
  # block to test translation units that need to gate DpdkBackend symbol
  # references.  Mirrors the parent-scope `target_compile_definitions`
  # pattern used for `HAVE_NUMACTL`.
  if(ENABLE_DPDK)
    target_compile_definitions("${test_we}" PRIVATE HAVE_DPDK)
  endif()

  gtest_discover_tests("${test_we}")
endforeach()

foreach(bench_src ${PACKET_ENGINE_BENCH_SOURCES})
  if(NOT IS_ABSOLUTE "${bench_src}")
    set(bench_src "${CMAKE_CURRENT_SOURCE_DIR}/${bench_src}")
  endif()
  get_filename_component(bench_we "${bench_src}" NAME_WE)
  get_filename_component(bench_file "${bench_src}" NAME)
  add_executable("${bench_we}" "${bench_src}")
  target_link_libraries("${bench_we}" PRIVATE GTest::gtest_main)
  target_include_directories("${bench_we}" PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  if(NOT "${bench_file}" IN_LIST PACKET_ENGINE_NO_CORE_TESTS
     AND TARGET packet_engine_core)
    target_link_libraries("${bench_we}" PRIVATE packet_engine_core)
  endif()
  if(TARGET packet_engine_prometheus)
    target_link_libraries("${bench_we}" PRIVATE packet_engine_prometheus)
  endif()
  if(NUMACTL_FOUND)
    target_include_directories("${bench_we}" SYSTEM PRIVATE ${NUMACTL_INCLUDE_DIRS})
    target_link_libraries("${bench_we}" PRIVATE ${NUMACTL_LIBRARIES})
    target_compile_definitions("${bench_we}" PRIVATE HAVE_NUMACTL=1)
  endif()
  gtest_discover_tests("${bench_we}")
endforeach()

if(ENABLE_DPDK)
  add_test(
    NAME dpdk_pcap_cli
    COMMAND bash
            ${CMAKE_CURRENT_SOURCE_DIR}/integration/test_dpdk_pcap_cli.sh
            $<TARGET_FILE:packet-engine>
  )
  set_tests_properties(dpdk_pcap_cli PROPERTIES
    RUN_SERIAL TRUE
    TIMEOUT 20
    LABELS integration
  )

  add_test(
    NAME dpdk_pcap_benchmark
    COMMAND bash
            ${CMAKE_CURRENT_SOURCE_DIR}/integration/test_pcap_benchmark.sh
            $<TARGET_FILE:packet-engine>
  )
  set_tests_properties(dpdk_pcap_benchmark PROPERTIES
    RUN_SERIAL TRUE
    TIMEOUT 120
    LABELS "benchmark;integration"
  )
endif()
