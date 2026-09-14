/*
 * See gui_worker.h. Windows keeps using Interlocked* for the cross-thread
 * cancel flag exactly as before (ARCHITECTURE.md section 2's windows.h
 * exception); Phase 16 adds a C11 <stdatomic.h> path for POSIX, which is
 * what lets the web GUI (Linux/macOS) reuse this file for scan
 * orchestration instead of a second, drifting copy of the same logic.
 */
#include "gui_worker.h"

#include <stdlib.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

void gui_cancel_flag_init(gui_cancel_flag_t *flag)
{
    if (flag == NULL) {
        return;
    }
#if defined(_WIN32)
    flag->requested = 0;
#else
    atomic_init(&flag->requested, 0);
#endif
}

void gui_cancel_flag_set(gui_cancel_flag_t *flag)
{
    if (flag == NULL) {
        return;
    }
#if defined(_WIN32)
    InterlockedExchange(&flag->requested, 1);
#else
    atomic_store(&flag->requested, 1);
#endif
}

usbs_bool gui_cancel_flag_is_set(const gui_cancel_flag_t *flag)
{
    if (flag == NULL) {
        return false;
    }
#if defined(_WIN32)
    /* InterlockedCompareExchange needs a non-const pointer; comparing 0
     * with 0 is a read that never mutates, and keeps this consistent with
     * the writer's memory ordering rather than an unordered plain read. */
    return InterlockedCompareExchange((volatile long *)&flag->requested, 0, 0) != 0;
#else
    /* atomic_load()'s parameter is not const-qualified even though a load
     * never mutates the object; cast away const explicitly, the same
     * "read via a mutation-shaped API" accommodation the Windows branch
     * above needs too. */
    return atomic_load((atomic_int *)&flag->requested) != 0;
#endif
}

static usbs_bool worker_cancel_check(void *ctx)
{
    return gui_cancel_flag_is_set((const gui_cancel_flag_t *)ctx);
}

static void worker_progress_thunk(void *ctx, const usbs_scan_progress_t *progress)
{
    const gui_worker_args_t *args = (const gui_worker_args_t *)ctx;
    if (args->on_progress != NULL) {
        args->on_progress(args->progress_ctx, progress);
    }
}

void gui_worker_run(const gui_worker_args_t *args)
{
    usbs_scan_result_t *result;
    usbs_status_t        status;

    if (args == NULL) {
        return;
    }

    result = (usbs_scan_result_t *)malloc(sizeof(*result));
    if (result == NULL) {
        if (args->on_done != NULL) {
            args->on_done(args->done_ctx, USBS_ERR_NO_MEMORY, NULL);
        }
        return;
    }

    status = usbs_scanner_scan(&args->device, args->store,
                               args->cancel_flag != NULL ? worker_cancel_check : NULL,
                               (void *)args->cancel_flag,
                               args->on_progress != NULL ? worker_progress_thunk : NULL,
                               (void *)args,
                               result);

    if (!usbs_ok(status)) {
        free(result);
        result = NULL;
    }

    if (args->on_done != NULL) {
        args->on_done(args->done_ctx, status, result);
    } else if (result != NULL) {
        usbs_scan_result_free(result);
        free(result);
    }
}

usbs_bool gui_should_auto_scan(const usbs_device_t *device,
                               usbs_bool            auto_scan_enabled,
                               usbs_bool            already_scanning,
                               usbs_bool            already_auto_scanned_this_identity)
{
    return usbs_device_is_scannable_usb(device) &&
           auto_scan_enabled && !already_scanning && !already_auto_scanned_this_identity;
}
