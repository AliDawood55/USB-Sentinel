# One backend per host, selected here rather than by #ifdef inside each file
# (Phase 14, ARCHITECTURE.md section 20.5).
#
# Before Phase 14 both Win32 sources were compiled unconditionally and carried
# an `#else` half full of USBS_ERR_UNSUPPORTED stubs, because that was the
# only way a non-Windows build could link. Now that a real POSIX backend
# exists, keeping that shape would mean two live implementations interleaved
# by preprocessor in one file. Selecting sources instead keeps each file a
# single implementation, and platform_unsupported.c preserves the property
# the old `#else` branches provided: an unfamiliar host still links.
#
# CMAKE_SYSTEM_NAME rather than CMake's LINUX/APPLE convenience variables --
# LINUX needs CMake 3.25 and this project declares 3.21.

if(WIN32)
    set(USBS_PLATFORM_SOURCES
        device_win32.c
        fs_win32.c)
elseif(UNIX)
    set(USBS_PLATFORM_SOURCES
        device_posix.c
        fs_posix.c
        hash_posix.c)

    # device_posix.c above holds only what is genuinely OS-independent
    # (status_from_win32's stub, cancellation). Device enumeration and
    # capability probing are OS-specific (ARCHITECTURE.md section 21)
    # and each host gets exactly one of the following, the same "one
    # backend per host" rule section 20.5 applies everywhere else.
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        list(APPEND USBS_PLATFORM_SOURCES device_linux.c)
    elseif(APPLE)
        list(APPEND USBS_PLATFORM_SOURCES device_macos.c)
    else()
        # Any other UNIX (a BSD, say) - enumeration and capability probing
        # honestly report USBS_ERR_UNSUPPORTED, matching the property
        # section 20.5 established for the whole platform layer, now
        # scoped to just the piece that is genuinely OS-specific.
        # scan <path> (section 20.11) still works there.
        list(APPEND USBS_PLATFORM_SOURCES device_posix_unsupported.c)
    endif()

    # The vendored SHA-256 is compiled only where no first-party provider
    # exists. macOS has CommonCrypto in libSystem and Windows has CNG; Linux
    # has neither, so this is the one host that needs it (see sha256.h).
    if(NOT APPLE AND NOT USBS_USE_OPENSSL)
        list(APPEND USBS_PLATFORM_SOURCES sha256.c)
    endif()
else()
    message(WARNING
        "No platform backend for ${CMAKE_SYSTEM_NAME}; building the "
        "unsupported fallback. The core will compile and the test suite's "
        "core_only subset will pass, but no scanning is possible.")
    set(USBS_PLATFORM_SOURCES platform_unsupported.c)
endif()

add_library(usbs_platform STATIC ${USBS_PLATFORM_SOURCES})

target_link_libraries(usbs_platform PUBLIC usbs_core)

if(WIN32)
    # OS import libraries only - no third-party dependency.
    # setupapi/cfgmgr32: device identity. WMI is deliberately not used;
    # see ARCHITECTURE.md section 7.1. bcrypt: SHA-256 via Windows CNG,
    # see ARCHITECTURE.md's Phase 4 notes. mpr: WNetGetConnectionW, to
    # resolve a mapped network drive to its share (Phase 17, section 23.1).
    target_link_libraries(usbs_platform PRIVATE setupapi cfgmgr32 bcrypt mpr)
elseif(APPLE)
    # CommonCrypto lives in libSystem, which is linked into every binary on
    # this platform, so there is deliberately no target_link_libraries call
    # for it here -- the include alone is sufficient.
    #
    # IOKit + DiskArbitration + CoreFoundation (Phase 14b.3): first-party
    # Apple frameworks, always present with the OS - no new dependency, the
    # same "OS import libraries only" stance as the Windows branch above
    # (setupapi/cfgmgr32/bcrypt). DiskArbitration supplies mount point,
    # label, filesystem, capacity, removable and bus-protocol in one call;
    # IOKit's registry is walked separately, only for USB VID/PID/serial
    # (ARCHITECTURE.md section 21.3).
    find_library(IOKIT_FRAMEWORK IOKit REQUIRED)
    find_library(DISKARBITRATION_FRAMEWORK DiskArbitration REQUIRED)
    find_library(COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
    target_link_libraries(usbs_platform PRIVATE
        ${IOKIT_FRAMEWORK}
        ${DISKARBITRATION_FRAMEWORK}
        ${COREFOUNDATION_FRAMEWORK})
elseif(UNIX AND USBS_USE_OPENSSL)
    # Opt-in only, for distribution packagers who would rather link the
    # system crypto library than ship a vendored primitive. Never the
    # default: it is the project's only third-party runtime dependency.
    find_package(OpenSSL REQUIRED)
    target_link_libraries(usbs_platform PRIVATE OpenSSL::Crypto)
    target_compile_definitions(usbs_platform PRIVATE USBS_USE_OPENSSL)
endif()
