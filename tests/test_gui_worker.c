/*
 * Headless test of gui_worker_run() (src/gui/gui_worker.c) - Phase 8's
 * testable GUI core. Exercises cancellation and progress/completion
 * callback plumbing on the calling thread, with no window, no
 * _beginthreadex, and no real hardware - the same "run the real engine
 * against a scratch directory" approach tests/test_scanner.c already uses
 * for the engine itself (ARCHITECTURE.md section 14.5).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "gui_worker.h"
#include "test_util.h"
#include "usbsentinel/path.h"
#include "usbsentinel/platform.h"
#include "usbsentinel/storage.h"

static void make_scratch_root(char *out, size_t cap)
{
    static usbs_bool seeded = false;
    if (!seeded) {
        srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)out);
        seeded = true;
    }
    snprintf(out, cap, "test_gui_worker_scratch_%08x" USBS_PATH_SEP, (unsigned)rand());
}

static void make_device(usbs_device_t *device, const char *root)
{
    memset(device, 0, sizeof(*device));
    snprintf(device->volume_path, sizeof(device->volume_path), "%s", root);
    device->bus_type      = USBS_BUS_USB;
    device->media_present = true;
}

static void make_store(usbs_store_t *store)
{
    char root[260];
    make_scratch_root(root, sizeof(root));
    root[strlen(root) - 1] = '\0';
    USBS_CHECK(usbs_ok(usbs_store_open_at(root, store)));
}

typedef struct capture {
    int           progress_calls;
    usbs_u64      last_files;
    int           done_calls;
    usbs_status_t done_status;
    usbs_scan_result_t *done_result;
} capture_t;

static void on_progress(void *ctx, const usbs_scan_progress_t *progress)
{
    capture_t *cap = (capture_t *)ctx;
    ++cap->progress_calls;
    cap->last_files = progress->files_scanned;
}

static void on_done(void *ctx, usbs_status_t status, usbs_scan_result_t *result)
{
    capture_t *cap = (capture_t *)ctx;
    ++cap->done_calls;
    cap->done_status = status;
    cap->done_result = result;
}

static void test_worker_runs_to_completion(void)
{
    char                root[260];
    char                path[320];
    int                 i;
    usbs_store_t        store;
    gui_worker_args_t   args;
    capture_t           cap;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    for (i = 0; i < 5; ++i) {
        snprintf(path, sizeof(path), "%sfile%d.txt", root, i);
        usbs_platform_write_file(path, "data", 4);
    }
    make_store(&store);

    memset(&args, 0, sizeof(args));
    make_device(&args.device, root);
    args.store        = &store;
    args.cancel_flag  = NULL;
    args.on_progress  = on_progress;
    args.progress_ctx = &cap;
    args.on_done      = on_done;
    args.done_ctx     = &cap;

    memset(&cap, 0, sizeof(cap));
    gui_worker_run(&args);

    USBS_CHECK(cap.done_calls == 1);
    USBS_CHECK(usbs_ok(cap.done_status));
    USBS_CHECK(cap.done_result != NULL);
    USBS_CHECK(cap.progress_calls == 5);
    USBS_CHECK(cap.last_files == 5);
    if (cap.done_result != NULL) {
        USBS_CHECK(cap.done_result->status == USBS_SCAN_COMPLETED);
        usbs_scan_result_free(cap.done_result);
        free(cap.done_result);
    }
}

/* A flag set before the scan even starts must stop the walk at (or very
 * near) the first file, exactly like Ctrl+C stops usbs_scanner_scan()
 * directly (tests/test_scanner.c's test_cancellation) - gui_worker_run()
 * only wires the flag through, it does not add its own cancellation
 * semantics. */
static void test_worker_honors_cancel_flag(void)
{
    char                root[260];
    char                path[320];
    int                 i;
    usbs_store_t        store;
    gui_worker_args_t   args;
    gui_cancel_flag_t   cancel_flag;
    capture_t           cap;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    for (i = 0; i < 20; ++i) {
        snprintf(path, sizeof(path), "%sfile%d.txt", root, i);
        usbs_platform_write_file(path, "data", 4);
    }
    make_store(&store);

    gui_cancel_flag_init(&cancel_flag);
    gui_cancel_flag_set(&cancel_flag);
    USBS_CHECK(gui_cancel_flag_is_set(&cancel_flag));

    memset(&args, 0, sizeof(args));
    make_device(&args.device, root);
    args.store       = &store;
    args.cancel_flag = &cancel_flag;
    args.on_done     = on_done;
    args.done_ctx    = &cap;

    memset(&cap, 0, sizeof(cap));
    gui_worker_run(&args);

    USBS_CHECK(cap.done_calls == 1);
    USBS_CHECK(usbs_ok(cap.done_status));
    USBS_CHECK(cap.done_result != NULL);
    if (cap.done_result != NULL) {
        USBS_CHECK(cap.done_result->status == USBS_SCAN_ABORTED);
        usbs_scan_result_free(cap.done_result);
        free(cap.done_result);
    }
}

/* With every callback left NULL (as a caller that does not care about the
 * outcome might do), gui_worker_run() must still run the scan to
 * completion and free the result itself - not crash, not leak. */
static void test_worker_no_callbacks_is_safe(void)
{
    char                root[260];
    usbs_store_t        store;
    gui_worker_args_t   args;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    make_store(&store);

    memset(&args, 0, sizeof(args));
    make_device(&args.device, root);
    args.store = &store;

    gui_worker_run(&args);
    USBS_CHECK(true); /* reaching here without crashing is the assertion */
}

/*
 * Phase 9: gui_should_auto_scan() is the pure decision pulled out of
 * gui_window.c's WM_DEVICECHANGE handling - exhaustively checkable here
 * without a window or a real device event, unlike the handling itself.
 */
static void test_should_auto_scan_decision(void)
{
    USBS_CHECK(gui_should_auto_scan(true, false, false) == true);
    USBS_CHECK(gui_should_auto_scan(false, false, false) == false); /* opt-in off */
    USBS_CHECK(gui_should_auto_scan(true, true, false) == false);   /* already scanning */
    USBS_CHECK(gui_should_auto_scan(true, false, true) == false);   /* seen this identity already */
    USBS_CHECK(gui_should_auto_scan(false, true, true) == false);
}

int main(void)
{
    test_worker_runs_to_completion();
    test_worker_honors_cancel_flag();
    test_worker_no_callbacks_is_safe();
    test_should_auto_scan_decision();
    return USBS_TEST_RESULT();
}
