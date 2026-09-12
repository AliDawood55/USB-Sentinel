add_library(usbs_platform STATIC
    device_win32.c
    fs_win32.c)

target_link_libraries(usbs_platform PUBLIC usbs_core)

if(WIN32)
    # OS import libraries only - no third-party dependency.
    # setupapi/cfgmgr32: device identity. WMI is deliberately not used;
    # see ARCHITECTURE.md section 7.1. bcrypt: SHA-256 via Windows CNG,
    # see ARCHITECTURE.md's Phase 4 notes.
    target_link_libraries(usbs_platform PRIVATE setupapi cfgmgr32 bcrypt)
endif()
