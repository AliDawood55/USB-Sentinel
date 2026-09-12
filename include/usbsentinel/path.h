/*
 * USB Sentinel - path separator handling.
 *
 * Portable C17, no platform headers (ARCHITECTURE.md section 2). This is
 * about the *shape* of a path string, which the layers above platform have
 * to build and take apart; the actual filesystem calls stay behind
 * platform.h.
 *
 * Introduced in Phase 14 (ARCHITECTURE.md section 20.7) with five real
 * consumers already - scanner, storage, hash_match, cli and the test scratch
 * roots - all of which had a "\\" typed directly into a format string. That
 * is comfortably past this project's usual bar for extracting a shared
 * helper.
 */
#ifndef USBSENTINEL_PATH_H
#define USBSENTINEL_PATH_H

#include <stddef.h>

#include "usbsentinel/error.h"
#include "usbsentinel/types.h"

/*
 * The separator this host builds paths with.
 *
 * Windows must use a backslash rather than simply accepting "/" everywhere:
 * the Win32 API tolerates forward slashes in ordinary paths, but NOT in the
 * "\\?\" long-path and volume-GUID forms, and usbs_device_t.volume_path is
 * exactly such a form (section 7.2). So this genuinely has to vary by host
 * rather than picking the one character both accept.
 */
#if defined(_WIN32)
#define USBS_PATH_SEP      "\\"
#define USBS_PATH_SEP_CHAR '\\'
#else
#define USBS_PATH_SEP      "/"
#define USBS_PATH_SEP_CHAR '/'
#endif

/*
 * True if `c` separates components of a path *on this host*.
 *
 * Asymmetric on purpose. Windows accepts both, so both must be recognised
 * when taking a path apart. POSIX accepts only "/" - and a backslash is a
 * perfectly legal byte in a POSIX filename, so treating it as a separator
 * there would silently mangle the basename of a file named `a\b.txt`.
 *
 * This is for host paths only. Content parsed *out of* a file - the target
 * and argument strings inside a .lnk, say - is Windows-shaped no matter
 * which host is reading it, and must keep testing for a backslash directly.
 */
usbs_bool usbs_path_is_separator(char c);

/*
 * Joins `base` and `leaf` with exactly one separator, writing to `out`.
 *
 * A trailing separator already on `base` is not doubled - callers hand this
 * both bare directory paths and volume paths, and usbs_device_t.volume_path
 * carries a trailing separator by definition. Returns USBS_ERR_NO_MEMORY if
 * the result would not fit (bounded, never truncated into `out` silently)
 * and USBS_ERR_INVALID_ARG for NULL arguments.
 */
usbs_status_t usbs_path_join(char *out, size_t cap, const char *base, const char *leaf);

#endif /* USBSENTINEL_PATH_H */
