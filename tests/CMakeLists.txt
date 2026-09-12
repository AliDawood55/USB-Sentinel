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
set(USBS_TEST_LIBS_test_gui_worker usbs_gui;usbs_scanner;usbs_storage;usbs_reporting;usbs_platform)
set(USBS_TEST_LIBS_test_gui_report_view usbs_gui;usbs_scanner;usbs_storage;usbs_reporting;usbs_platform)

set(USBS_TESTS
    test_version
    test_error
    test_log
    test_json
    test_env
    test_device
    test_platform
    test_hash
    test_storage
    test_detectors
    test_lnk
    test_hash_match
    test_signature_list
    test_scanner
    test_report)

# The GUI tests link usbs_gui, which only exists on Windows (see the root
# CMakeLists). They are appended rather than listed above so the portable set
# stays the default and Windows is the addition, not the other way round.
if(WIN32)
    list(APPEND USBS_TESTS
        test_gui_worker
        test_gui_report_view)
endif()

# Phase 14: which tests can run before the POSIX platform backend exists.
#
# `core_only` tests touch no usbs_platform entry point at all, so they are
# meaningful on any host the project compiles on, today. Everything else
# reaches the filesystem, hashing or device layer through platform.h, and on
# a POSIX host those still resolve to the USBS_ERR_UNSUPPORTED stubs - such
# a test fails for a reason that says nothing about the code under test.
#
# CI runs `-L core_only` on Linux/macOS and the full suite on Windows. When
# fs_posix.c lands, the POSIX jobs run the full suite too and this label
# stops carrying any scheduling meaning - it is a temporary scaffold, and
# deliberately labelled by what the tests *are* rather than by which
# platform happens to run them.
set(USBS_CORE_ONLY_TESTS
    test_version
    test_error
    test_log
    test_json
    test_env
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
