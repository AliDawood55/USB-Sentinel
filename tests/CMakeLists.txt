# Each test is a standalone executable registered with CTest. No external
# test framework: see tests/test_util.h.
#
# Device/platform tests run through a fixture source or assert only
# invariants, so they need no hardware. Storage/scanner/detector tests use a
# real temporary directory (via usbs_store_open_at / a scratch folder) rather
# than a fake filesystem seam - filesystem operations are generic OS
# operations, not USB-specific, so this needs no hardware either and avoids
# building a second, speculative fs seam alongside the one Phase 2 already
# built for device enumeration.
set(USBS_TEST_LIBS_test_version   usbs_core)
set(USBS_TEST_LIBS_test_error     usbs_core)
set(USBS_TEST_LIBS_test_log       usbs_core)
set(USBS_TEST_LIBS_test_json      usbs_core)
set(USBS_TEST_LIBS_test_env       usbs_core)
set(USBS_TEST_LIBS_test_location  usbs_core)
set(USBS_TEST_LIBS_test_device    usbs_platform)
set(USBS_TEST_LIBS_test_platform  usbs_platform)
set(USBS_TEST_LIBS_test_hash      usbs_platform)
set(USBS_TEST_LIBS_test_storage   usbs_storage;usbs_platform)
set(USBS_TEST_LIBS_test_detectors usbs_detectors;usbs_platform)
set(USBS_TEST_LIBS_test_lnk       usbs_detectors;usbs_platform)
set(USBS_TEST_LIBS_test_hash_match usbs_detectors;usbs_platform)
set(USBS_TEST_LIBS_test_signature_list usbs_detectors;usbs_platform)
set(USBS_TEST_LIBS_test_scanner   usbs_scanner;usbs_storage;usbs_platform)
set(USBS_TEST_LIBS_test_report    usbs_reporting)
# usbs_cli PUBLICly links usbs_core and usbs_platform (src/cli/CMakeLists.txt),
# so linking it alone brings in everything usbs_cli_build_path_device() and
# this test's own fixture setup need.
set(USBS_TEST_LIBS_test_cmd_scan  usbs_cli)
set(USBS_TEST_LIBS_test_device_linux usbs_platform)
set(USBS_TEST_LIBS_test_gui_worker usbs_gui_core;usbs_scanner;usbs_storage;usbs_reporting;usbs_platform)
set(USBS_TEST_LIBS_test_gui_report_view usbs_gui_core;usbs_scanner;usbs_storage;usbs_reporting;usbs_platform)
set(USBS_TEST_LIBS_test_http_server usbs_gui_web)

set(USBS_TESTS
    test_version
    test_error
    test_log
    test_json
    test_env
    test_location
    test_device
    test_platform
    test_hash
    test_storage
    test_detectors
    test_lnk
    test_hash_match
    test_signature_list
    test_scanner
    test_report
    test_cmd_scan
    test_gui_worker
    test_gui_report_view)

# test_device_linux.c exercises device_linux.c's internal test-only seam
# (usbs_linux_device_source_at()) directly and creates real symlinks for
# its own fixtures - meaningful, and buildable, only where that file is
# actually compiled (ARCHITECTURE.md section 21).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND USBS_TESTS test_device_linux)
endif()

# test_http_server.c links usbs_gui_web, which only exists where the
# Phase 16 web GUI is built (root CMakeLists' if(UNIX) gate).
if(UNIX)
    list(APPEND USBS_TESTS test_http_server)
endif()

# Phase 14: which tests can run before the POSIX platform backend exists.
#
# `core_only` tests touch no usbs_platform entry point at all, so they are
# meaningful on any host the project compiles on, today. Everything else
# reaches the filesystem, hashing or device layer through platform.h, and on
# a POSIX host those still resolve to the USBS_ERR_UNSUPPORTED stubs - such
# a test fails for a reason that says nothing about the code under test.
#
# CI ran `-L core_only` on Linux/macOS between Phase 14 steps 2 and 4, while
# the POSIX backend did not yet exist. It no longer does: every platform now
# runs the full suite. The label was deliberately named for what the tests
# *are* rather than for which platform happened to run them, so it stays
# accurate now that it carries no scheduling meaning - it still answers "what
# can be run on a host with no platform backend at all", which is exactly the
# question platform_unsupported.c exists for.
set(USBS_CORE_ONLY_TESTS
    test_version
    test_error
    test_log
    test_json
    test_env
    test_location
    test_device
    test_report)

foreach(test_name IN LISTS USBS_TESTS)
    add_executable(${test_name} "${test_name}.c")
    target_include_directories(${test_name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(${test_name} PRIVATE ${USBS_TEST_LIBS_${test_name}})
    add_test(NAME ${test_name} COMMAND ${test_name})

    if(${test_name} IN_LIST USBS_CORE_ONLY_TESTS)
        set_tests_properties(${test_name} PROPERTIES LABELS "core_only")
    endif()
endforeach()
