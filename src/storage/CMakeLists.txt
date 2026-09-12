add_library(usbs_storage STATIC
    storage.c)

target_link_libraries(usbs_storage PUBLIC usbs_core)
target_link_libraries(usbs_storage PRIVATE usbs_platform)
