/*
 * USB Sentinel - scan orchestration.
 *
 * Single-threaded, depth-first traversal (ARCHITECTURE.md's Phase 3
 * concurrency decision: simple first, no threading). Walks the device's
 * volume, runs every registered detector, and hands the finished report to
 * storage. See scanner.c for the per-file error isolation and
 * device-removal handling this module is responsible for.
 */
#ifndef USBSENTINEL_SCANNER_H
#define USBSENTINEL_SCANNER_H

#include "usbsentinel/scan.h"
#include "usbsentinel/storage.h"

/*
 * Returns true when the caller wants the scan to stop as soon as possible
 * (e.g. Ctrl+C was observed). Checked between files/directories, not inside
 * a single file's read loop - see scanner.c. May be NULL to disable
 * cancellation.
 */
typedef usbs_bool (*usbs_cancel_check_fn)(void *ctx);

/*
 * Progress snapshot handed to an optional progress callback (Phase 8): the
 * same counts file_traversal's final message reports, but observable while
 * the scan is still running.
 */
typedef struct usbs_scan_progress {
    usbs_u64 files_scanned;
    usbs_u64 bytes_scanned;
} usbs_scan_progress_t;

/*
 * Called once per file processed by the shared walk - the same granularity
 * usbs_cancel_check_fn is polled at. scanner.c calls this unconditionally
 * when non-NULL; a caller that wants to throttle how often it actually acts
 * on this (e.g. a GUI posting window messages) does so in its own callback,
 * not here - scanner stays ignorant of who is listening or how often they
 * want to hear from it. May be NULL to disable progress reporting.
 */
typedef void (*usbs_progress_fn)(void *ctx, const usbs_scan_progress_t *progress);

/*
 * Scans `device`'s volume: probes capabilities, looks up (and logs) any
 * prior scan of this device via `store`, walks the volume computing a
 * streaming digest per file, then runs every registered detector
 * (usbsentinel/detector.h). Always produces a usable *out_result - even a
 * cancelled or device-removed run yields USBS_SCAN_ABORTED with whatever was
 * collected before that point, not an error return. A non-OK return means
 * the scan could not even be attempted (bad arguments, storage lookup
 * failure).
 */
usbs_status_t usbs_scanner_scan(const usbs_device_t *device,
                                const usbs_store_t   *store,
                                usbs_cancel_check_fn  cancel_check,
                                void                 *cancel_ctx,
                                usbs_progress_fn      on_progress,
                                void                 *progress_ctx,
                                usbs_scan_result_t   *out_result);

#endif /* USBSENTINEL_SCANNER_H */
