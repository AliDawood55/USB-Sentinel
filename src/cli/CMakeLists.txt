add_library(usbs_cli STATIC
    cli.c
    cmd_devices.c
    cmd_scan.c)

target_include_directories(usbs_cli PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries(usbs_cli PUBLIC usbs_core usbs_platform)
target_link_libraries(usbs_cli PRIVATE usbs_scanner usbs_storage usbs_reporting)
