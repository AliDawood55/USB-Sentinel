add_library(usbs_reporting STATIC
    report.c)

target_link_libraries(usbs_reporting PUBLIC usbs_core)
