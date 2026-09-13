cmake_minimum_required(VERSION 3.21)

project(usb_sentinel
    VERSION 1.2.0
    DESCRIPTION "Offline-first USB malware scanning engine"
    LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# The GUI executable carries an icon and version information (Phase 11), so
# the resource compiler is needed -- but only on Windows, and only for that
# one target. Enabled here rather than in the project() call above so a
# non-Windows configure (which has no rc.exe) still succeeds for the
# portable core.
if(WIN32)
    enable_language(RC)
endif()

option(USBS_WERROR "Treat compiler warnings as errors" OFF)

# Phase 14: link the system crypto library instead of the vendored SHA-256.
# OFF by default and never used on Windows or macOS, both of which have a
# first-party provider (CNG, CommonCrypto). This exists for Linux
# distribution packagers whose policy forbids vendored crypto - it is the
# project's only optional third-party runtime dependency. See
# src/platform/sha256.h and ARCHITECTURE.md section 20.6.
option(USBS_USE_OPENSSL "Use OpenSSL's SHA-256 instead of the vendored one (POSIX, non-Apple)" OFF)

# Phase 12 hardening (ARCHITECTURE.md section 18): MSVC's native
# /fsanitize=address, exercised through its own x64-asan preset rather than
# folded into x64-debug/x64-release, since it changes the CRT/runtime-check
# flags those two presets must otherwise keep stable.
option(USBS_ASAN "Build with MSVC AddressSanitizer instrumentation" OFF)

# Phase 12 hardening: MSVC's static analyzer (PREfast, /analyze), run as its
# own preset rather than folded into every build - it materially slows
# compilation and its C6xxx diagnostics are triaged by hand (fixed or
# explicitly suppressed with a recorded reason), not treated as ordinary
# build warnings gated by USBS_WERROR.
option(USBS_ANALYZE "Build with MSVC static analysis (/analyze)" OFF)

# Shared compile settings for every USB Sentinel target.
add_library(usbs_options INTERFACE)

# UNICODE/_UNICODE select the wide-character forms of the Win32 API and mean
# nothing anywhere else, so they are scoped to Windows rather than defined for
# every target on every host (Phase 14).
if(WIN32)
    target_compile_definitions(usbs_options INTERFACE
        UNICODE
        _UNICODE)
endif()

# Phase 14: POSIX hosts need the 2008 POSIX feature set visible - openat,
# fstatat/AT_SYMLINK_NOFOLLOW, lstat, setenv/unsetenv. CMAKE_C_EXTENSIONS is
# OFF (so the compiler is invoked as -std=c17, not -std=gnu17), which means
# glibc exposes only the strict ISO C surface unless _POSIX_C_SOURCE says
# otherwise. Declared here, once, rather than as a #define at the top of each
# POSIX source file where it would have to precede every #include to work.
#
# _XOPEN_SOURCE=700 (Phase 14b): _POSIX_C_SOURCE=200809L alone is not
# sufficient for every function this project needs - realpath(), used by
# device_linux.c's USB ancestry walk, compiled with an implicit (and
# therefore int-truncated, on a 64-bit pointer) declaration under
# -std=c17 -D_POSIX_C_SOURCE=200809L alone, silently corrupting the
# returned pointer rather than failing to compile. Confirmed empirically
# (a minimal realpath() call, several feature-macro combinations tried
# against this project's actual glibc) rather than assumed from a man
# page: glibc gates realpath() behind the XSI-extension macro
# _XOPEN_SOURCE sets, which plain _POSIX_C_SOURCE does not activate on
# this version. 700 is the X/Open revision aligned with POSIX.1-2008, so
# it does not narrow anything _POSIX_C_SOURCE=200809L already granted.
if(UNIX)
    target_compile_definitions(usbs_options INTERFACE
        _POSIX_C_SOURCE=200809L
        _XOPEN_SOURCE=700)
    if(APPLE)
        # Darwin hides most of its BSD surface behind _DARWIN_C_SOURCE once
        # _POSIX_C_SOURCE is set; without this, _POSIX_C_SOURCE alone removes
        # declarations this project uses on macOS.
        target_compile_definitions(usbs_options INTERFACE
            _DARWIN_C_SOURCE)
    endif()
endif()

if(MSVC)
    target_compile_options(usbs_options INTERFACE /W4 /permissive-)
    if(USBS_WERROR)
        target_compile_options(usbs_options INTERFACE /WX)
    endif()
else()
    target_compile_options(usbs_options INTERFACE -Wall -Wextra -Wpedantic)
    if(USBS_WERROR)
        target_compile_options(usbs_options INTERFACE -Werror)
    endif()
endif()

if(USBS_ASAN)
    if(NOT MSVC)
        message(FATAL_ERROR "USBS_ASAN is implemented for MSVC's /fsanitize=address only")
    endif()

    # /RTC1 (MSVC's default Debug runtime checks) and /fsanitize=address
    # both instrument the same categories of bug and the compiler refuses
    # to combine them ("/RTC1 and /fsanitize=address are incompatible").
    # ASan is the strictly stronger tool here, so /RTC1 is stripped from
    # the Debug flags rather than declining ASan support for Debug builds.
    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}" CACHE STRING
        "Flags used by the C compiler during DEBUG builds." FORCE)

    target_compile_options(usbs_options INTERFACE /fsanitize=address)

    # CMake's Ninja/MSVC generator links via link.exe directly rather than
    # through the cl.exe driver, so the automatic ASan-runtime-library
    # selection cl.exe normally performs at link time does not happen here.
    # The libraries below (and /INCREMENTAL:NO, which ASan's instrumentation
    # is documented as incompatible with) must be supplied explicitly.
    # Verified empirically against this toolchain's actual
    # VC\Tools\MSVC\<ver>\lib\x64 contents, not assumed from documentation
    # alone - see ARCHITECTURE.md section 18.
    # Confirmed by listing this toolchain's actual lib\x64 directory: there
    # is one dynamic-CRT ASan runtime per configuration (dbg vs release) but
    # only a single runtime-thunk library, shared by both.
    target_link_options(usbs_options INTERFACE /INCREMENTAL:NO)
    target_link_libraries(usbs_options INTERFACE
        $<$<CONFIG:Debug>:clang_rt.asan_dbg_dynamic-x86_64.lib>
        $<$<NOT:$<CONFIG:Debug>>:clang_rt.asan_dynamic-x86_64.lib>)
    target_link_options(usbs_options INTERFACE
        /wholearchive:clang_rt.asan_dynamic_runtime_thunk-x86_64.lib)
endif()

if(USBS_ANALYZE)
    if(NOT MSVC)
        message(FATAL_ERROR "USBS_ANALYZE is implemented for MSVC's /analyze only")
    endif()
    # /analyze:external- keeps PREfast from reporting inside system/SDK
    # headers included with angle brackets (<windows.h> and friends) -
    # this project's own hand-written code is what the audit is for.
    target_compile_options(usbs_options INTERFACE /analyze /analyze:external-)
endif()

# version.h is generated so the version lives in exactly one place: this file.
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/usbsentinel/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/usbsentinel/version.h"
    @ONLY)

enable_testing()

add_subdirectory(src/core)
add_subdirectory(src/platform)
add_subdirectory(src/storage)
add_subdirectory(src/detectors)
add_subdirectory(src/scanner)
add_subdirectory(src/reporting)
add_subdirectory(src/cli)
add_subdirectory(src/app)

# src/gui builds unconditionally: usbs_gui_core (gui_worker.c +
# gui_report_view.c) is windows.h-free since Phase 16 and is what the
# Phase 16 web GUI (src/gui_web/, added below) reuses for scan
# orchestration. The actual Win32 window (usbs_gui, gui_window.c - one of
# only three files in the project that includes <windows.h>) and its
# entry point (src/app_gui, a WIN32 executable built from a generated
# .rc) cannot configure on a POSIX host, so those two stay gated here;
# src/gui/CMakeLists.txt itself gates usbs_gui internally the same way.
add_subdirectory(src/gui)
if(WIN32)
    add_subdirectory(src/app_gui)
endif()

# Phase 16: a browser-based GUI for Linux/macOS - a local HTTP server
# (raw POSIX sockets, no third-party HTTP library) serving an embedded
# single-page frontend, standing in for the native Win32 window that
# cannot be ported (ARCHITECTURE.md section 22). UNIX rather than
# NOT WIN32 or "not Windows": deliberately excludes any future non-UNIX,
# non-Windows target this project has never considered, rather than
# silently opting one in.
if(UNIX)
    add_subdirectory(src/gui_web)
    add_subdirectory(src/app_gui_web)
endif()

add_subdirectory(tests)

# --- Packaging (Phase 10; extended Phase 15 for a Linux .tar.gz) ---
#
# Two mutually exclusive per-platform generator blocks below. WIN32
# produces the existing NSIS installer for the GUI; Linux (UNIX and not
# APPLE -- macOS packaging stays deferred alongside its GUI, per Phase
# 14's platform-support table) produces a plain .tar.gz of the CLI
# executable and README, which is all there is to package on a
# platform with no GUI build. A macOS host configures straight past
# this block entirely.
if(WIN32 OR (UNIX AND NOT APPLE))

set(CPACK_PACKAGE_NAME "USB Sentinel")
set(CPACK_PACKAGE_VENDOR "USB Sentinel")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")

if(WIN32)
#
# Per-user NSIS installer via CPack. The NSIS-specific customizations
# (forcing no elevation, a real per-user install path, and the opt-in
# "launch at login" shortcut) live in packaging/usbs_installer_extra.nsh
# rather than inline CMake strings: CPack re-serializes CPACK_NSIS_*
# string values into CPackConfig.cmake as plain double-quoted CMake
# strings without re-escaping embedded backslashes, so any Windows path
# written directly into those variables fails to reparse. Referencing
# the .nsh file by path avoids that -- CMAKE_CURRENT_SOURCE_DIR always
# renders with forward slashes. See that file and ARCHITECTURE.md S16
# for the full investigation.

set(CPACK_PACKAGE_INSTALL_DIRECTORY "USB Sentinel")
set(CPACK_PACKAGE_EXECUTABLES "usb-sentinel-gui" "USB Sentinel")
set(CPACK_NSIS_EXECUTABLES_DIRECTORY "bin")

set(CPACK_GENERATOR "NSIS")
set(CPACK_NSIS_DISPLAY_NAME "USB Sentinel")
set(CPACK_NSIS_PACKAGE_NAME "USB Sentinel")
# A forward slash here compiles fine (unlike !include, above), but ends
# up producing InstallDir "$LOCALAPPDATA/Programs\USB Sentinel" (mixed
# separators) in the generated script for any account UsbsFixInstallContext
# does not override -- i.e. a genuinely standard, non-admin account,
# which is exactly the case that keeps CPACK_NSIS_INSTALL_ROOT's value
# instead of the Documents-then-corrected path. Rather than rely on
# assumed Win32 tolerance for that (already wrong once today about "/"
# in NSIS), doubled the same way as CPACK_NSIS_DEFINES so a real
# backslash survives the CPackConfig.cmake round-trip.
string(REPLACE "\\" "\\\\" CPACK_NSIS_INSTALL_ROOT [[$LOCALAPPDATA\Programs]])
set(CPACK_NSIS_IGNORE_LICENSE_PAGE ON)
set(CPACK_NSIS_MODIFY_PATH OFF)
set(CPACK_NSIS_UNINSTALL_NAME "Uninstall USB Sentinel")

# NSIS's !include is a compile-time directive handled by the NSIS
# compiler itself, unlike runtime path instructions (CreateShortCut,
# StrCpy, ...) that go through Win32 APIs tolerant of "/" -- confirmed
# by direct isolation testing (four minimal .nsi scripts, one per
# quote/slash combination): a forward-slash path here fails with
# "!include: could not find", regardless of quoting; only a backslash
# path resolves. That is the opposite of what CPackConfig.cmake's
# non-re-escaping round-trip (see the comment above CPACK_NSIS_DEFINES'
# original forward-slash form, and ARCHITECTURE.md S16.5/S16.8) can
# carry safely as a single backslash, so the stored value must contain
# *doubled* backslashes -- CPack's dump writes them out verbatim as
# "\\", which is what a normal quoted CMake string needs to reparse
# back down to a single "\" on the second pass. Built with file()/
# string() rather than hand-typed backslash counts, which is exactly
# the kind of thing that is easy to miscount and hard to visually
# verify.
file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/packaging/usbs_installer_extra.nsh" USBS_NSH_NATIVE_PATH)
string(REPLACE "\\" "\\\\" USBS_NSH_ESCAPED_PATH "${USBS_NSH_NATIVE_PATH}")
set(CPACK_NSIS_DEFINES "!include ${USBS_NSH_ESCAPED_PATH}")
set(CPACK_NSIS_EXTRA_PREINSTALL_COMMANDS "!insertmacro UsbsFixInstallContext")
set(CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "!insertmacro UsbsUninstallExtra")

# Installer branding (Phase 11). These are paths CPack writes into
# CPackConfig.cmake and NSIS then reads, so they need the same doubled
# backslashes the !include path above does -- CPack re-serializes these
# values without re-escaping, and NSIS treats a backslash in a string as
# significant. Built with file()/string() rather than hand-counted
# backslashes for the same reason given there.
file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/resources/usb-sentinel.ico" USBS_ICON_NATIVE_PATH)
string(REPLACE "\\" "\\\\" USBS_ICON_ESCAPED_PATH "${USBS_ICON_NATIVE_PATH}")
set(CPACK_NSIS_MUI_ICON "${USBS_ICON_ESCAPED_PATH}")
set(CPACK_NSIS_MUI_UNIICON "${USBS_ICON_ESCAPED_PATH}")

# The icon shown in Settings > Apps (and the legacy Add/Remove Programs
# list). Relative to $INSTDIR, so it points at the installed executable and
# picks up the icon compiled into it -- one icon, one source of truth.
string(REPLACE "\\" "\\\\" CPACK_NSIS_INSTALLED_ICON_NAME [[bin\usb-sentinel-gui.exe]])

elseif(UNIX AND NOT APPLE)
#
# Phase 15: a plain .tar.gz containing the CLI executable (installed to
# bin/ by src/app/CMakeLists.txt's own install(TARGETS ...), which runs
# unconditionally on every platform) and the README. There is no GUI or
# installer to build here (see the Platform support table in
# README.md), so a tarball of the CLI is the whole of Linux packaging.
set(CPACK_GENERATOR "TGZ")
set(CPACK_PACKAGE_FILE_NAME "usb-sentinel-${PROJECT_VERSION}-linux-x86_64")

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/README.md" DESTINATION .)

endif()

include(CPack)

endif() # WIN32 OR (UNIX AND NOT APPLE) -- packaging
