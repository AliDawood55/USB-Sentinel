/*
 * USB Sentinel - portable environment-variable access.
 *
 * A small, deliberately narrow wrapper: storage.c and (from Phase 6)
 * detectors/signature_list-adjacent code in hash_match.c both need the same
 * _dupenv_s (MSVC) / getenv (portable) dance to resolve %LOCALAPPDATA% and
 * an optional override variable - a genuine second and third real consumer,
 * the bar this project applies before extracting a shared helper (see
 * ARCHITECTURE.md's repeated "wait for the real need" stance).
 */
#ifndef USBSENTINEL_ENV_H
#define USBSENTINEL_ENV_H

#include <stddef.h>

#include "usbsentinel/error.h"

/*
 * Copies the value of environment variable `name` into `out` (bounded,
 * always NUL-terminated on success). Returns USBS_ERR_NOT_FOUND if the
 * variable is unset or empty (empty is treated the same as unset - an
 * accidentally-blank variable should not silently resolve to an empty
 * path), USBS_ERR_NO_MEMORY if `out` is too small, USBS_ERR_INVALID_ARG for
 * NULL arguments.
 */
usbs_status_t usbs_getenv(const char *name, char *out, size_t cap);

/*
 * Sets environment variable `name` to `value` for the remainder of this
 * process (and any child process it spawns - not relevant here, but the
 * standard semantics). Used to pass `scan --signatures <path>` down to
 * hash_match.c without cli reaching directly into a specific detector's
 * internals (see hash_match.c's header comment), and by tests that need to
 * point a detector at a fixture file. `value` of NULL or "" clears it.
 */
usbs_status_t usbs_setenv(const char *name, const char *value);

/*
 * Writes this application's per-user data directory into `out` - the root
 * under which `storage` keeps reports and from which `hash_match` loads its
 * default signature list.
 *
 * Each platform has one answer, and it is a platform convention rather than
 * a preference (Phase 14, ARCHITECTURE.md section 20.7):
 *
 *   Windows  %LOCALAPPDATA%\USBSentinel
 *   macOS    $HOME/Library/Application Support/USBSentinel
 *   Linux    $XDG_DATA_HOME/usb-sentinel, else $HOME/.local/share/usb-sentinel
 *
 * The Linux name is lowercase-hyphenated because that is the XDG convention
 * and matches the installed binary's name; the Windows and macOS forms are
 * title-cased because those platforms' conventions are. Deliberately not
 * unified into one spelling - matching each platform matters more than
 * matching ourselves across platforms, and on Windows the existing
 * %LOCALAPPDATA%\USBSentinel directory already holds v1.0.0 users' reports.
 *
 * Returns USBS_ERR_NOT_FOUND when the environment gives no usable home
 * directory, which callers already treat as "no resolvable store".
 */
usbs_status_t usbs_user_data_dir(char *out, size_t cap);

#endif /* USBSENTINEL_ENV_H */
