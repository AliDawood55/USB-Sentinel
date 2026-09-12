/*
 * See gui_worker.h. The only Win32 this file uses is Interlocked* for the
 * cross-thread cancel flag - ARCHITECTURE.md section 2's windows.h
 * exception now covers gui/ alongside platform/ (section 14).
 */
#include "gui_worker.h"

#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void gui_cancel_flag_init(gui_cancel_flag_t *flag)
{
    if (flag == NULL) {
        return;
    }
    flag->requested = 0;
}

void gui_cancel_flag_set(gui_cancel_flag_t *flag)
{
    if (flag == NULL) {
        return;
    }
    InterlockedExchange(&flag->requested, 1);
}

usbs_bool gui_cancel_flag_is_set(const gui_cancel_flag_t *flag)
{
    if (flag == NULL) {
        return false;
    }
    /* InterlockedCompareExchange needs a non-const pointer; comparing 0
     * with 0 is a read that never mutates, and keeps this consistent with
     * the writer's memory ordering rather than an unordered plain read. */
    return InterlockedCompareExchange((volatile long *)&flag->requested, 0, 0) != 0;
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

usbs_bool gui_should_auto_scan(usbs_bool auto_scan_enabled,
                               usbs_bool already_scanning,
                               usbs_bool already_auto_scanned_this_identity)
{
    return auto_scan_enabled && !already_scanning && !already_auto_scanned_this_identity;
}
