/*
 * USB Sentinel - platform boundary.
 *
 * Everything that touches Win32 lives behind this header. Callers above the
 * platform layer branch on capabilities, never on privilege
 * (ARCHITECTURE.md section 7.3).
 */
#ifndef USBSENTINEL_PLATFORM_H
#define USBSENTINEL_PLATFORM_H

#include "usbsentinel/device.h"
#include "usbsentinel/error.h"
#include "usbsentinel/types.h"

/*
 * What the current process is actually able to do with a given device.
 *
 * These are probed by attempting the operation, not by asking whether the user
 * is an administrator: under UAC's split token those are different questions,
 * and only "can this process open that handle" matters.
 */
typedef struct usbs_capabilities {
    usbs_bool can_read_raw_volume;    /* \\.\X: opened for reading */
    usbs_bool can_read_physical_disk; /* \\.\PhysicalDriveN opened for reading */
} usbs_capabilities_t;

/* Zeroes `caps`. */
void usbs_capabilities_init(usbs_capabilities_t *caps);

/*
 * Probes what `device` permits. Never fails on access denial: a refused handle
 * is a result, recorded as false, not an error. Returns USBS_ERR_INVALID_ARG
 * only for NULL arguments and USBS_ERR_UNSUPPORTED on non-Windows builds.
 */
usbs_status_t usbs_platform_probe_capabilities(const usbs_device_t *device,
                                               usbs_capabilities_t *out_caps);

/*
 * The live Win32 enumeration source. Returns a source whose `enumerate` is
 * NULL on non-Windows builds, which usbs_device_enumerate() reports as
 * USBS_ERR_UNSUPPORTED.
 */
usbs_device_source_t usbs_platform_device_source(void);

/*
 * Translates a Win32 error code (as returned by GetLastError) into a status.
 * Exposed for tests; callers should not need it, because platform functions
 * never let a Win32 code escape upward.
 */
usbs_status_t usbs_platform_status_from_win32(unsigned long win32_error);

/* ---------------------------------------------------------------------- *
 * Directory traversal and read-only file access.
 *
 * Scanner and detectors need to walk directories and read file bytes on a
 * scanned volume. That still touches Win32 (wide paths, long-path support
 * via the \\?\ prefix already used for volume_path, explicit share modes
 * per the read-only policy in ARCHITECTURE.md section 1) so it stays behind
 * this boundary rather than letting scanner or detectors include windows.h
 * themselves (section 2). Paths in and out are UTF-8, like usbs_device_t.
 * ---------------------------------------------------------------------- */

#define USBS_NAME_MAX 260

typedef struct usbs_dir_entry {
    char      name[USBS_NAME_MAX]; /* file/dir name only, not a full path */
    usbs_bool is_directory;
    usbs_bool is_reparse_point;    /* junction/symlink; traversal must not follow */
    usbs_bool is_hidden;           /* hidden or system attribute set */
    usbs_u64  size_bytes;          /* 0 for directories */
} usbs_dir_entry_t;

typedef struct usbs_dir_iter usbs_dir_iter_t; /* opaque */

/* Opens `utf8_path` (a directory) for listing. */
usbs_status_t usbs_platform_dir_open(const char *utf8_path, usbs_dir_iter_t **out_iter);

/*
 * Advances to the next entry, skipping "." and "..". Returns USBS_ERR_NOT_FOUND
 * once the listing is exhausted - that is the normal end-of-iteration signal,
 * not a failure.
 */
usbs_status_t usbs_platform_dir_next(usbs_dir_iter_t *iter, usbs_dir_entry_t *out_entry);

void usbs_platform_dir_close(usbs_dir_iter_t *iter);

typedef struct usbs_file usbs_file_t; /* opaque, read-only handle */

/* Opens `utf8_path` for reading only, sharing read+write with other processes
 * (never write access - the read-only policy in ARCHITECTURE.md section 1). */
usbs_status_t usbs_platform_file_open_read(const char *utf8_path, usbs_file_t **out_file);

/*
 * Reads up to `cap` bytes into `buf`. *out_read == 0 with USBS_OK signals
 * end of file, not an error.
 */
usbs_status_t usbs_platform_file_read(usbs_file_t *file, void *buf, size_t cap,
                                      size_t *out_read);

void usbs_platform_file_close(usbs_file_t *file);

/* ---------------------------------------------------------------------- *
 * Local data store writes - for `storage`'s own on-disk files ONLY (the
 * report/index files under %LOCALAPPDATA%\USBSentinel; see ARCHITECTURE.md's
 * detection-data-format decision). Never used on a scanned device: keeping
 * this separate from usbs_platform_file_open_read/read/close above means
 * scanner and detectors are never even handed an API that could write to
 * scanned content, which is what makes the read-only policy in section 1 an
 * absence-of-capability guarantee, not just a convention.
 * ---------------------------------------------------------------------- */

/* Creates `utf8_path` and any missing parent directories. Succeeds if the
 * directory already exists. */
usbs_status_t usbs_platform_make_dirs(const char *utf8_path);

/* Creates or truncates `utf8_path` and writes `len` bytes of `data`. */
usbs_status_t usbs_platform_write_file(const char *utf8_path, const void *data, size_t len);

/*
 * Atomically replaces `dest` with `src` (same-volume rename). This is the
 * second half of the temp-file-then-rename pattern storage uses for
 * corruption resistance. If `dest` does not exist, this simply names `src`
 * as `dest`.
 */
usbs_status_t usbs_platform_replace_file(const char *dest, const char *src);

/* Deletes `utf8_path` if it exists; not an error if it does not. Used to
 * clean up a temp file after a failed replace. */
usbs_status_t usbs_platform_delete_file(const char *utf8_path);

/* ---------------------------------------------------------------------- *
 * Cancellation. Ctrl+C handling is inherently Win32 (SetConsoleCtrlHandler),
 * so it stays behind this boundary; callers only ever see a plain flag.
 * ---------------------------------------------------------------------- */

/*
 * Installs a Ctrl+C/Ctrl+Break handler that sets an internal flag, polled via
 * usbs_platform_cancel_requested(). Idempotent. Returns USBS_ERR_UNSUPPORTED
 * on non-Windows builds; a scan then simply cannot be cancelled this way and
 * runs to completion, which is a safe (not silently wrong) degradation.
 */
usbs_status_t usbs_platform_install_cancel_handler(void);

/* True once the handler above has observed a cancellation request. */
usbs_bool usbs_platform_cancel_requested(void);

/* ---------------------------------------------------------------------- *
 * SHA-256, via Windows CNG (bcrypt.dll) - a first-party facility, not a
 * hand-rolled implementation and not a third-party dependency, matching how
 * SetupAPI/CfgMgr32 were preferred over WMI in ARCHITECTURE.md section 7.1.
 * Streaming, so it composes with the same bounded-buffer read loops already
 * used for file content (see detectors). Computed only where a detector
 * actually calls it - never as an unconditional whole-volume pass; see
 * ARCHITECTURE.md's Phase 4 notes.
 * ---------------------------------------------------------------------- */

#define USBS_SHA256_DIGEST_SIZE 32
#define USBS_SHA256_HEX_LEN     64 /* + 1 for the NUL terminator */

typedef struct usbs_hash_ctx usbs_hash_ctx_t; /* opaque */

/* Starts a new SHA-256 computation. */
usbs_status_t usbs_platform_hash_begin(usbs_hash_ctx_t **out_ctx);

/* Feeds `len` bytes into the computation. A `len` of 0 is a no-op. */
usbs_status_t usbs_platform_hash_update(usbs_hash_ctx_t *ctx, const void *data, size_t len);

/*
 * Finishes the computation and frees `ctx` (valid whether this call succeeds
 * or fails - never call usbs_platform_hash_abort() afterward). `out_digest`
 * receives the 32 raw bytes; `out_hex`, if non-NULL, receives the lowercase
 * hex string plus terminator (needs at least USBS_SHA256_HEX_LEN + 1 bytes).
 */
usbs_status_t usbs_platform_hash_finish(usbs_hash_ctx_t *ctx,
                                        unsigned char     out_digest[USBS_SHA256_DIGEST_SIZE],
                                        char              *out_hex);

/* Frees `ctx` without finishing (e.g. on an error path). NULL-safe. */
void usbs_platform_hash_abort(usbs_hash_ctx_t *ctx);

#endif /* USBSENTINEL_PLATFORM_H */
