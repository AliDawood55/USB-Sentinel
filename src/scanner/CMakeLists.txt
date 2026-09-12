add_library(usbs_scanner STATIC
    scanner.c)

target_link_libraries(usbs_scanner PUBLIC usbs_core)
target_link_libraries(usbs_scanner PRIVATE usbs_platform usbs_storage usbs_detectors)
