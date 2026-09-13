# usbs_gui_core: the portable scan-orchestration/report-summarization
# core (gui_worker.c + gui_report_view.c) - windows.h-free since Phase 16
# (gui_worker.c's cancel flag moved to <stdatomic.h>), built on every
# platform. The Phase 16 web GUI (src/gui_web/, Linux/macOS) links this
# directly rather than duplicating scan orchestration; usbs_gui below
# adds gui_window.c, the actual Win32 window, and stays Windows-only.
add_library(usbs_gui_core STATIC
    gui_worker.c
    gui_report_view.c)

target_include_directories(usbs_gui_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries(usbs_gui_core PUBLIC usbs_core usbs_platform)
target_link_libraries(usbs_gui_core PRIVATE usbs_scanner usbs_storage usbs_reporting)

if(WIN32)
    add_library(usbs_gui STATIC
        gui_window.c)

    target_link_libraries(usbs_gui PUBLIC usbs_gui_core)

    # OS import libraries only - no third-party dependency, mirroring
    # platform's own setupapi/cfgmgr32/bcrypt linkage (ARCHITECTURE.md
    # section 14). comctl32: the progress bar control. shell32: "Open
    # Reports Folder" (ShellExecuteW).
    target_link_libraries(usbs_gui PRIVATE user32 gdi32 comctl32 shell32)
endif()
