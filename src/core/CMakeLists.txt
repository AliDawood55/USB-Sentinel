add_library(usbs_core STATIC
    device.c
    env.c
    error.c
    json.c
    log.c
    path.c
    scan.c
    version.c)

target_include_directories(usbs_core PUBLIC
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_BINARY_DIR}/generated")

target_link_libraries(usbs_core PUBLIC usbs_options)
