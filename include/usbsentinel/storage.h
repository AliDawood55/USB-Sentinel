/*
 * USB Sentinel - local scan-report persistence.
 *
 * Layout, atomicity, and the index cache: see ARCHITECTURE.md's Phase 3
 * detection-data-format decision. This module owns the on-disk layout;
 * nothing above it (scanner, reporting) should assume a file naming scheme
 * or directory structure - they go through this API.
 *
 * Depends only on core. It does not depend on platform's device model:
 * callers pass the already-computed device identity string
 * (usbs_device_identity()), not a usbs_device_t.
 */
#ifndef USBSENTINEL_STORAGE_H
#define USBSENTINEL_STORAGE_H

#include "usbsentinel/error.h"
#include "usbsentinel/types.h"

#define USBS_STORE_PATH_MAX 512

typedef struct usbs_store {
    char root[USBS_STORE_PATH_MAX]; /* e.g. "C:\Users\name\AppData\Local\USBSentinel" */
} usbs_store_t;

/*
 * Resolves the store root from %LOCALAPPDATA%\USBSentinel and ensures it
 * exists. Fails with USBS_ERR_NOT_FOUND if LOCALAPPDATA is not set (not
 * expected in a normal interactive or service-with-profile session).
 */
usbs_status_t usbs_store_open(usbs_store_t *out_store);

/*
 * Same as usbs_store_open(), but rooted at an explicit directory instead of
 * %LOCALAPPDATA%. Exists for tests, so storage behavior can be exercised
 * against a scratch directory with no dependency on the real user profile.
 */
usbs_status_t usbs_store_open_at(const char *root, usbs_store_t *out_store);

/*
 * Encodes `device_identity` (as usbs_device_identity() produces it) into a
 * string safe to use as a single path component: alphanumerics, '.', '-',
 * '_' pass through; every other byte becomes "_XX" (uppercase hex). This is
 * a reversible-in-spirit but not reversed encoding - collisions are avoided,
 * not readability preserved. Exposed for tests.
 */
usbs_status_t usbs_store_safe_id(const char *device_identity, char *out, size_t cap);

typedef struct usbs_store_last_scan {
    char      scan_id[64];
    char      scanned_at[32]; /* ISO-8601 UTC, recovered from the filename */
    size_t    report_count;
    usbs_bool found;
} usbs_store_last_scan_t;

/*
 * Reports the most recent prior scan of `device_identity`, derived by
 * listing that device's report directory - never by trusting index.json,
 * so a corrupt or missing index cannot make this answer wrong. `found` is
 * false (not an error) when the device has never been scanned before.
 */
usbs_status_t usbs_store_last_scan(const usbs_store_t     *store,
                                   const char              *device_identity,
                                   usbs_store_last_scan_t *out_info);

/*
 * Writes `json_text` as a new report for `device_identity`, named
 * "<timestamp_utc>-<scan_id>.json". The write is atomic (temp file, fsync,
 * rename): a reader never observes a partial file, and a crash or device
 * removal mid-write leaves at most an orphaned .tmp file, never a corrupt
 * report. Refreshes index.json afterward on a best-effort basis; a failure
 * there does not fail the write, since the index is a rebuildable cache.
 *
 * `out_path` (optional) receives the full path written, for logging.
 */
usbs_status_t usbs_store_write_report(const usbs_store_t *store,
                                      const char          *device_identity,
                                      const char          *scan_id,
                                      const char          *timestamp_utc,
                                      const char          *json_text,
                                      size_t               json_len,
                                      char                *out_path,
                                      size_t               out_path_cap);

/*
 * Writes `csv_text` as a companion file for the same report (Phase 7) -
 * same directory and "<timestamp>-<scan_id>" stem as
 * usbs_store_write_report(), ".csv" instead of ".json", same atomic
 * temp-file-then-rename guarantee. Does not refresh index.json itself: it
 * is meant to be called for the same (device_identity, scan_id,
 * timestamp_utc) already passed to usbs_store_write_report(), whose call
 * already covers the refresh for this scan - call order between the two
 * does not matter.
 */
usbs_status_t usbs_store_write_report_csv(const usbs_store_t *store,
                                          const char          *device_identity,
                                          const char          *scan_id,
                                          const char          *timestamp_utc,
                                          const char          *csv_text,
                                          size_t               csv_len,
                                          char                *out_path,
                                          size_t               out_path_cap);

#endif /* USBSENTINEL_STORAGE_H */
