# Phase 16: the web GUI's HTTP layer and route handlers. usbs_gui_core
# (src/gui/, portable since Phase 16) supplies scan orchestration; this
# library adds raw-socket HTTP (http_server.c) and the application logic
# (gui_web_app.c) that wires the two together, plus the embedded
# frontend generated from assets/index.html below. Only ever built
# UNIX-only (the root CMakeLists' if(UNIX) gate) - see http_server.c's
# own header comment for the POSIX APIs (sockets, select()) this relies
# on.
set(USBS_GUI_WEB_ASSET_C "${CMAKE_CURRENT_BINARY_DIR}/gui_web_index_html.c")

add_custom_command(
    OUTPUT "${USBS_GUI_WEB_ASSET_C}"
    COMMAND "${CMAKE_COMMAND}"
        "-DINPUT_FILE=${CMAKE_CURRENT_SOURCE_DIR}/assets/index.html"
        "-DOUTPUT_FILE=${USBS_GUI_WEB_ASSET_C}"
        "-DVAR_NAME=gui_web_index_html"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/EmbedAsset.cmake"
    DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/assets/index.html"
        "${CMAKE_CURRENT_SOURCE_DIR}/EmbedAsset.cmake"
    COMMENT "Embedding gui_web/assets/index.html into the web GUI binary")

# pthreads: the one new build-time dependency this module adds (a
# standard part of any POSIX toolchain, not a third-party library -
# see gui_worker.h's own comment on why MSVC's <stdatomic.h>
# restriction kept this off the Windows build entirely).
find_package(Threads REQUIRED)

add_library(usbs_gui_web STATIC
    http_server.c
    gui_web_app.c
    "${USBS_GUI_WEB_ASSET_C}")

target_include_directories(usbs_gui_web PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")

# gui_worker.h is module-internal to src/gui/ (not under
# include/usbsentinel/), reused here directly rather than duplicated -
# see gui_web_app.c's own header comment.
target_include_directories(usbs_gui_web PRIVATE
    "${CMAKE_SOURCE_DIR}/src/gui")

target_link_libraries(usbs_gui_web PUBLIC usbs_core usbs_platform)
target_link_libraries(usbs_gui_web PRIVATE
    usbs_gui_core
    usbs_scanner
    usbs_storage
    usbs_reporting
    Threads::Threads)
