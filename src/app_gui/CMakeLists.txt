# The resource script is generated rather than checked in so the icon and
# the shared id header can be referenced by ABSOLUTE path: rc.exe then needs
# no include directory of its own, which is one fewer assumption about how
# the resource compiler resolves relative paths (this project has been
# caught once already by exactly that class of assumption -- see the NSIS
# !include investigation in ARCHITECTURE.md S16.8).
#
# Backslashes are doubled because a backslash is an escape character inside
# an RC string literal.
file(TO_NATIVE_PATH "${CMAKE_SOURCE_DIR}/resources/usb-sentinel.ico" USBS_ICON_NATIVE)
string(REPLACE "\\" "\\\\" USBS_APP_ICON_PATH "${USBS_ICON_NATIVE}")

file(TO_NATIVE_PATH "${CMAKE_SOURCE_DIR}/src/gui/usbs_gui_resource.h" USBS_RESOURCE_HEADER_NATIVE)
string(REPLACE "\\" "\\\\" USBS_GUI_RESOURCE_HEADER "${USBS_RESOURCE_HEADER_NATIVE}")

configure_file(
    "${CMAKE_SOURCE_DIR}/resources/usb_sentinel_gui.rc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/usb_sentinel_gui.rc"
    @ONLY)

add_executable(usb_sentinel_gui WIN32
    main_gui.c
    "${CMAKE_CURRENT_BINARY_DIR}/usb_sentinel_gui.rc")

set_target_properties(usb_sentinel_gui PROPERTIES
    OUTPUT_NAME "usb-sentinel-gui")

target_link_libraries(usb_sentinel_gui PRIVATE usbs_gui)

install(TARGETS usb_sentinel_gui
    RUNTIME DESTINATION bin)
