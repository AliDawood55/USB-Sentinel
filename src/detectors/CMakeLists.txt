add_library(usbs_detectors STATIC
    autorun.c
    hash_match.c
    lnk_inspect.c
    registry.c
    signature_list.c
    suspicious_filename.c)

target_link_libraries(usbs_detectors PUBLIC usbs_core)
target_link_libraries(usbs_detectors PRIVATE usbs_platform)
