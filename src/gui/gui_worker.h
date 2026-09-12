/*
 * USB Sentinel - GUI worker: runs one scan off the UI thread.
 *
 * This is Phase 8's testable core. It knows how to run a scan and report
 * progress/completion through plain callbacks; it does not know about
 * HWNDs, window messages, or _beginthreadex - gui_window.c supplies those
 * as a thin layer on top (ARCHITECTURE.md section 14). That split is what
 * lets tests/test_gui_worker.c exercise cancellation and progress/
 * completion plumbing with no window and no real worker thread: it just
 * calls gui_worker_run() directly, on the test's own thread - the same
 * "pure core, thin platform-specific wrapper" split already used for
 * usbs_hash_match_lookup() (ARCHITECTURE.md section 11.3).
 *
 * Module-internal, like cli.h: not part of the cross-module surface in
 * include/usbsentinel/.
 */
#ifndef USBS_GUI_WORKER_H
#define USBS_GUI_WORKER_H

#include "usbsentinel/device.h"
#include "usbsentinel/scanner.h"
#include "usbsentinel/storage.h"
#include "usbsentinel/types.h"

/*
 * A flag safe to set from one thread and poll from another
 * (InterlockedExchange/InterlockedCompareExchange - see gui_worker.c).
 * gui_window.c sets this when Cancel is clicked; gui_worker_run() wires it
 * to usbs_scanner_scan() as its usbs_cancel_check_fn.
 */
typedef struct gui_cancel_flag {
    volatile long requested;
} gui_cancel_flag_t;

/* NULL-safe, like the functions below. */
void      gui_cancel_flag_init(gui_cancel_flag_t *flag);
void      gui_cancel_flag_set(gui_cancel_flag_t *flag);
usbs_bool gui_cancel_flag_is_set(const gui_cancel_flag_t *flag);

/* Same shape as usbs_progress_fn: NULL disables it. */
typedef void (*gui_worker_progress_fn)(void *ctx, const usbs_scan_progress_t *progress);

/*
 * Reports the scan's outcome, exactly once, at the end of gui_worker_run().
 * `result` is heap-allocated (malloc'd by gui_worker_run()); the callback
 * takes ownership and must eventually usbs_scan_result_free() + free() it.
 * `result` is NULL only when `status` is not USBS_OK (the scan could not
 * even be attempted, e.g. an allocation failure) - callers must check
 * `status` before touching `result`. May be NULL, in which case
 * gui_worker_run() frees the result itself and reports nothing - only
 * useful for a caller that does not care about the outcome.
 */
typedef void (*gui_worker_done_fn)(void *ctx, usbs_status_t status, usbs_scan_result_t *result);

typedef struct gui_worker_args {
    usbs_device_t       device; /* copied by value before the scan starts */
    const usbs_store_t *store;  /* must outlive the call */
    gui_cancel_flag_t  *cancel_flag; /* must outlive the call; may be NULL */

    gui_worker_progress_fn on_progress; /* may be NULL */
    void                   *progress_ctx;
    gui_worker_done_fn      on_done;    /* may be NULL - see above */
    void                    *done_ctx;
} gui_worker_args_t;

/*
 * Runs one scan to completion, synchronously, on the calling thread -
 * gui_window.c calls this from a _beginthreadex worker thread; tests call
 * it directly on their own thread. See the module comment above.
 */
void gui_worker_run(const gui_worker_args_t *args);

/*
 * Phase 9: the hot-plug auto-scan decision, pulled out of gui_window.c's
 * WM_DEVICECHANGE handling so it is testable without a window or a real
 * device event (tests/test_gui_worker.c) - the same "thin Win32 plumbing,
 * pure testable decision" split as the rest of this module.
 *
 * True only when auto-scan is enabled, nothing is currently scanning, and
 * this device identity has not already been auto-scanned since it was
 * last seen absent (gui_window.c's auto-scanned set tracks that last
 * part; this function only combines the three booleans).
 */
usbs_bool gui_should_auto_scan(usbs_bool auto_scan_enabled,
                               usbs_bool already_scanning,
                               usbs_bool already_auto_scanned_this_identity);

#endif /* USBS_GUI_WORKER_H */
