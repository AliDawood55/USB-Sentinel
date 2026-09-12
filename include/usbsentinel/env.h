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

#endif /* USBSENTINEL_ENV_H */
