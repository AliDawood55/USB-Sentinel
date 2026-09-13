add_executable(usb_sentinel_gui_web main.c)

set_target_properties(usb_sentinel_gui_web PROPERTIES
    OUTPUT_NAME "usb-sentinel-gui-web")

target_link_libraries(usb_sentinel_gui_web PRIVATE usbs_gui_web usbs_storage)

install(TARGETS usb_sentinel_gui_web
    RUNTIME DESTINATION bin)
