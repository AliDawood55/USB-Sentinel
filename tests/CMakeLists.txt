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
    test_report
    test_gui_worker
    test_gui_report_view)

foreach(test_name IN LISTS USBS_TESTS)
    add_executable(${test_name} "${test_name}.c")
    target_include_directories(${test_name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(${test_name} PRIVATE ${USBS_TEST_LIBS_${test_name}})
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
