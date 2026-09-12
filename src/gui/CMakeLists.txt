add_library(usbs_gui STATIC
    gui_worker.c
    gui_report_view.c
    gui_window.c)

target_include_directories(usbs_gui PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries(usbs_gui PUBLIC usbs_core usbs_platform)
target_link_libraries(usbs_gui PRIVATE usbs_scanner usbs_storage usbs_reporting)

if(WIN32)
    # OS import libraries only - no third-party dependency, mirroring
    # platform's own setupapi/cfgmgr32/bcrypt linkage (ARCHITECTURE.md
    # section 14). comctl32: the progress bar control. shell32: "Open
    # Reports Folder" (ShellExecuteW).
    target_link_libraries(usbs_gui PRIVATE user32 gdi32 comctl32 shell32)
endif()
