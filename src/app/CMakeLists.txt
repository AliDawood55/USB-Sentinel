add_executable(usb_sentinel
    main.c)

set_target_properties(usb_sentinel PROPERTIES
    OUTPUT_NAME "usb-sentinel")

target_link_libraries(usb_sentinel PRIVATE usbs_cli)

install(TARGETS usb_sentinel
    RUNTIME DESTINATION bin)
