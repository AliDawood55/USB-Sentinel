/*
 * Scanner tests run the real traversal against a scratch directory standing
 * in for a volume root - no USB hardware needed for traversal, cancellation,
 * or per-file error isolation.
 *
 * The one device-removal test needs several files that are unreadable at
 * scan time (to exercise "repeated I/O failures look like device removal"),
 * which this test simulates by holding them open with no sharing - the only
 * reason this file, unlike the rest of the test suite, touches <windows.h>
 * directly. That is fixture setup, not product code, so it does not bear on
 * ARCHITECTURE.md section 2's "platform is the only module permitted to
 * include windows.h" rule, which governs src/, not tests/.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "test_util.h"
#include "usbsentinel/platform.h"
#include "usbsentinel/scanner.h"
#include "usbsentinel/storage.h"

static void make_scratch_root(char *out, size_t cap)
{
    static usbs_bool seeded = false;
    if (!seeded) {
        srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)out);
        seeded = true;
    }
    snprintf(out, cap, "test_scanner_scratch_%08x\\", (unsigned)rand());
}

static void make_device(usbs_device_t *device, const char *root)
{
    memset(device, 0, sizeof(*device));
    snprintf(device->volume_path, sizeof(device->volume_path), "%s", root);
    device->bus_type      = USBS_BUS_USB;
    device->media_present = true;
    snprintf(device->usb_vid, sizeof(device->usb_vid), "0000");
    snprintf(device->usb_pid, sizeof(device->usb_pid), "0001");
}

static void make_store(usbs_store_t *store)
{
    char root[260];
    make_scratch_root(root, sizeof(root));
    /* trim trailing backslash: usbs_store_open_at treats its argument as a
     * plain directory path, not a volume-style path. */
    root[strlen(root) - 1] = '\0';
    USBS_CHECK(usbs_ok(usbs_store_open_at(root, store)));
}

static const usbs_check_result_t *find_check(const usbs_scan_result_t *result, const char *id)
{
    size_t i;
    for (i = 0; i < result->checks.count; ++i) {
        if (strcmp(result->checks.items[i].id, id) == 0) {
            return &result->checks.items[i];
        }
    }
    return NULL;
}

static void test_invalid_args(void)
{
    usbs_device_t       device;
    usbs_store_t         store;
    usbs_scan_result_t   result;

    memset(&device, 0, sizeof(device));
    make_store(&store);

    USBS_CHECK(usbs_scanner_scan(NULL, &store, NULL, NULL, NULL, NULL, &result) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_scanner_scan(&device, NULL, NULL, NULL, NULL, NULL, &result) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_scanner_scan(&device, &store, NULL, NULL, NULL, NULL, NULL) == USBS_ERR_INVALID_ARG);
}

static void test_basic_scan_completes(void)
{
    char                root[260];
    char                path[320];
    usbs_device_t       device;
    usbs_store_t        store;
    usbs_scan_result_t  result;
    const usbs_check_result_t *traversal;
    const usbs_check_result_t *autorun;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%sa.txt", root); usbs_platform_write_file(path, "hello", 5);
    snprintf(path, sizeof(path), "%sb.txt", root); usbs_platform_write_file(path, "world!", 6);
    snprintf(path, sizeof(path), "%ssub\\", root); usbs_platform_make_dirs(path);
    snprintf(path, sizeof(path), "%ssub\\c.txt", root); usbs_platform_write_file(path, "x", 1);

    make_device(&device, root);
    make_store(&store);

    USBS_CHECK(usbs_ok(usbs_scanner_scan(&device, &store, NULL, NULL, NULL, NULL, &result)));
    USBS_CHECK(result.status == USBS_SCAN_COMPLETED);
    USBS_CHECK(result.scan_id[0] != '\0');
    USBS_CHECK(result.started_at[0] != '\0');
    USBS_CHECK(result.finished_at[0] != '\0');

    traversal = find_check(&result, "file_traversal");
    USBS_CHECK(traversal != NULL);
    USBS_CHECK(traversal->status == USBS_CHECK_RAN);
    USBS_CHECK(strstr(traversal->message, "completed") != NULL);
    USBS_CHECK(strstr(traversal->message, "3 file(s)") != NULL);

    autorun = find_check(&result, "autorun_inspection");
    USBS_CHECK(autorun != NULL);
    USBS_CHECK(autorun->status == USBS_CHECK_RAN);
    USBS_CHECK(autorun->findings.count == 0);

    usbs_scan_result_free(&result);
}

static void test_missing_root_is_a_failed_traversal(void)
{
    usbs_device_t       device;
    usbs_store_t        store;
    usbs_scan_result_t  result;
    const usbs_check_result_t *traversal;
    const usbs_check_result_t *autorun;

    make_device(&device, "test_scanner_does_not_exist_at_all\\");
    make_store(&store);

    USBS_CHECK(usbs_ok(usbs_scanner_scan(&device, &store, NULL, NULL, NULL, NULL, &result)));
    USBS_CHECK(result.status == USBS_SCAN_ABORTED);

    traversal = find_check(&result, "file_traversal");
    USBS_CHECK(traversal != NULL);
    USBS_CHECK(traversal->status == USBS_CHECK_FAILED);

    autorun = find_check(&result, "autorun_inspection");
    USBS_CHECK(autorun != NULL);
    USBS_CHECK(autorun->status == USBS_CHECK_SKIPPED);
    USBS_CHECK(strstr(autorun->skip_reason, "could not be read") != NULL);

    /* The on_file detectors (Phase 5's new shape) must get the same
     * "skipped, never a misleading partial result" treatment as autorun -
     * both run and on_file style detectors share one incomplete-scan path
     * in scanner.c. */
    {
        const usbs_check_result_t *suspicious = find_check(&result, "suspicious_filename");
        const usbs_check_result_t *lnk        = find_check(&result, "lnk_inspection");
        const usbs_check_result_t *hash_match  = find_check(&result, "hash_match_example");

        USBS_CHECK(suspicious != NULL && suspicious->status == USBS_CHECK_SKIPPED);
        USBS_CHECK(lnk != NULL && lnk->status == USBS_CHECK_SKIPPED);
        USBS_CHECK(hash_match != NULL && hash_match->status == USBS_CHECK_SKIPPED);
    }

    usbs_scan_result_free(&result);
}

typedef struct cancel_after_n {
    int calls;
    int cancel_at;
} cancel_after_n_t;

static usbs_bool cancel_after_n(void *ctx)
{
    cancel_after_n_t *state = (cancel_after_n_t *)ctx;
    ++state->calls;
    return state->calls >= state->cancel_at;
}

static void test_cancellation(void)
{
    char                root[260];
    char                path[320];
    usbs_device_t       device;
    usbs_store_t        store;
    usbs_scan_result_t  result;
    cancel_after_n_t    cancel_state;
    int                 i;
    const usbs_check_result_t *traversal;
    const usbs_check_result_t *autorun;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    for (i = 0; i < 10; ++i) {
        snprintf(path, sizeof(path), "%sfile%d.txt", root, i);
        usbs_platform_write_file(path, "data", 4);
    }

    make_device(&device, root);
    make_store(&store);

    cancel_state.calls     = 0;
    cancel_state.cancel_at = 2; /* cancel almost immediately */

    USBS_CHECK(usbs_ok(usbs_scanner_scan(&device, &store, cancel_after_n, &cancel_state, NULL, NULL, &result)));
    USBS_CHECK(result.status == USBS_SCAN_ABORTED);

    traversal = find_check(&result, "file_traversal");
    USBS_CHECK(traversal != NULL);
    USBS_CHECK(traversal->status == USBS_CHECK_RAN); /* cancellation is not a failure */
    USBS_CHECK(strstr(traversal->message, "cancelled") != NULL);

    autorun = find_check(&result, "autorun_inspection");
    USBS_CHECK(autorun != NULL);
    USBS_CHECK(autorun->status == USBS_CHECK_SKIPPED);
    USBS_CHECK(strstr(autorun->skip_reason, "cancelled") != NULL);

    /* Same contract for the on_file detectors, including any partial
     * findings they collected before cancellation - discarded, not kept. */
    {
        const usbs_check_result_t *suspicious = find_check(&result, "suspicious_filename");
        USBS_CHECK(suspicious != NULL);
        USBS_CHECK(suspicious->status == USBS_CHECK_SKIPPED);
        USBS_CHECK(suspicious->findings.count == 0);
    }

    usbs_scan_result_free(&result);
}

/*
 * Phase 8: the progress callback exists so a GUI can show live counts while
 * a scan runs - see ARCHITECTURE.md section 14. Verifies it fires once per
 * file with non-decreasing counts and that the final call matches
 * file_traversal's own tally, without any GUI or extra thread involved.
 */
typedef struct progress_capture {
    usbs_u64 last_files;
    usbs_u64 last_bytes;
    int      calls;
} progress_capture_t;

static void capture_progress(void *ctx, const usbs_scan_progress_t *progress)
{
    progress_capture_t *state = (progress_capture_t *)ctx;
    USBS_CHECK(progress->files_scanned >= state->last_files);
    state->last_files = progress->files_scanned;
    state->last_bytes = progress->bytes_scanned;
    ++state->calls;
}

static void test_progress_callback_fires(void)
{
    char                root[260];
    char                path[320];
    usbs_device_t       device;
    usbs_store_t        store;
    usbs_scan_result_t  result;
    progress_capture_t  capture;
    int                 i;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    for (i = 0; i < 5; ++i) {
        snprintf(path, sizeof(path), "%sfile%d.txt", root, i);
        usbs_platform_write_file(path, "data", 4);
    }

    make_device(&device, root);
    make_store(&store);
    memset(&capture, 0, sizeof(capture));

    USBS_CHECK(usbs_ok(usbs_scanner_scan(&device, &store, NULL, NULL,
                                         capture_progress, &capture, &result)));
    USBS_CHECK(result.status == USBS_SCAN_COMPLETED);
    USBS_CHECK(capture.calls == 5);
    USBS_CHECK(capture.last_files == 5);
    USBS_CHECK(capture.last_bytes == 20); /* 5 files * 4 bytes ("data") */

    usbs_scan_result_free(&result);
}

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/*
 * Phase 4: the general traversal is metadata-only (it counts via
 * usbs_dir_entry_t.size_bytes and never opens file content - see
 * scanner.c). Locking every file with no sharing must therefore have NO
 * effect on the traversal outcome: it completes normally and counts them
 * all, proving content reads were genuinely removed from this path rather
 * than merely made to look removed.
 */
static void test_locked_files_do_not_affect_traversal(void)
{
    char                root[260];
    char                path[320];
    HANDLE              handles[5];
    int                 i;
    usbs_device_t       device;
    usbs_store_t        store;
    usbs_scan_result_t  result;
    const usbs_check_result_t *traversal;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));

    for (i = 0; i < 5; ++i) {
        wchar_t wide[400];
        snprintf(path, sizeof(path), "%slocked%d.bin", root, i);
        usbs_platform_write_file(path, "data", 4);
        MultiByteToWideChar(CP_UTF8, 0, path, -1, wide, (int)USBS_ARRAY_LEN(wide));
        /* No FILE_SHARE_READ: opening this file for content would fail, but
         * the traversal must never attempt to. */
        handles[i] = CreateFileW(wide, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        USBS_CHECK(handles[i] != INVALID_HANDLE_VALUE);
    }

    make_device(&device, root);
    make_store(&store);

    USBS_CHECK(usbs_ok(usbs_scanner_scan(&device, &store, NULL, NULL, NULL, NULL, &result)));
    USBS_CHECK(result.status == USBS_SCAN_COMPLETED);

    traversal = find_check(&result, "file_traversal");
    USBS_CHECK(traversal != NULL);
    USBS_CHECK(traversal->status == USBS_CHECK_RAN);
    USBS_CHECK(strstr(traversal->message, "completed") != NULL);
    USBS_CHECK(strstr(traversal->message, "5 file(s)") != NULL);
    /* 5 files * 4 bytes ("data"), counted from directory-listing metadata. */
    USBS_CHECK(strstr(traversal->message, "20 byte(s)") != NULL);

    usbs_scan_result_free(&result);

    for (i = 0; i < 5; ++i) {
        CloseHandle(handles[i]);
    }
}

#endif /* _WIN32 */

/*
 * Phase 5: scanner now owns a single shared walk dispatching to every
 * on_file detector (ARCHITECTURE.md's Phase 5 notes) instead of each
 * detector walking the volume independently. This proves the consolidation
 * actually reaches every detector: one fixture file with a disguised name
 * must be seen by suspicious_filename, and a scan of a whole tree must
 * still produce exactly four checks (autorun, suspicious_filename,
 * lnk_inspection, hash_match_example) with no detector silently missing.
 */
static void test_all_four_detectors_run_in_one_scan(void)
{
    char                root[260];
    char                path[320];
    usbs_device_t       device;
    usbs_store_t        store;
    usbs_scan_result_t  result;
    const usbs_check_result_t *suspicious;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%sordinary.txt", root);
    usbs_platform_write_file(path, "hello", 5);
    /* A disguised-executable name the suspicious_filename on_file callback
     * must catch during the same walk that also counts it for
     * file_traversal and hands it to lnk_inspect/hash_match (which correctly
     * find nothing, since it is neither a .lnk nor a known hash match). */
    snprintf(path, sizeof(path), "%sinvoice.pdf.exe", root);
    usbs_platform_write_file(path, "x", 1);

    make_device(&device, root);
    make_store(&store);

    USBS_CHECK(usbs_ok(usbs_scanner_scan(&device, &store, NULL, NULL, NULL, NULL, &result)));
    USBS_CHECK(result.status == USBS_SCAN_COMPLETED);
    USBS_CHECK(result.checks.count == 5); /* file_traversal + 4 detectors */

    USBS_CHECK(find_check(&result, "file_traversal") != NULL);
    USBS_CHECK(find_check(&result, "autorun_inspection") != NULL);
    USBS_CHECK(find_check(&result, "lnk_inspection") != NULL);
    USBS_CHECK(find_check(&result, "hash_match_example") != NULL);

    suspicious = find_check(&result, "suspicious_filename");
    USBS_CHECK(suspicious != NULL);
    USBS_CHECK(suspicious->status == USBS_CHECK_RAN);
    USBS_CHECK(suspicious->findings.count == 1);
    if (suspicious->findings.count == 1) {
        USBS_CHECK_STR_EQ(suspicious->findings.items[0].path, "invoice.pdf.exe");
        USBS_CHECK(strstr(suspicious->findings.items[0].message, "double extension") != NULL);
    }

    usbs_scan_result_free(&result);
}

/*
 * Phase 12 (ARCHITECTURE.md section 18): USBS_SCAN_MAX_DEPTH (scanner.c) is
 * 64, and walk_dir()'s guard is "depth > 64", so a directory is still
 * opened at depth 64 (the 65th directory in a chain rooted at depth 0) and
 * refused only from depth 65 onward. This builds a chain deeper than that
 * (70 levels) with one file at every level, so the boundary is exercised
 * directly against the real traversal rather than only reasoned about from
 * reading the guard - the same "verify against the real code, not by
 * inspection" discipline test_reader_depth_limit_applies_to_nested_objects
 * in test_json.c needed too (an initial off-by-one there was caught this
 * same way).
 */
static void test_deep_nesting_stops_at_scan_max_depth(void)
{
    enum { NESTING_LEVELS = 70, USBS_SCAN_MAX_DEPTH_UNDER_TEST = 64 };
    char                root[260];
    char                dir_path[1024];
    char                file_path[1040];
    int                 level;
    usbs_device_t       device;
    usbs_store_t        store;
    usbs_scan_result_t  result;
    const usbs_check_result_t *traversal;
    char                expect_msg[64];

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(dir_path, sizeof(dir_path), "%s", root);

    /* Level 0 is the root itself (depth 0 in walk_dir); level i's directory
     * is opened at depth i. A single-character name at every level keeps
     * the cumulative path comfortably under Windows' normal MAX_PATH, since
     * usbs_platform_make_dirs() (test-only helper here, mirroring storage's
     * own local writes) does not add the \\?\ long-path prefix a real
     * volume scan's walk uses (ARCHITECTURE.md section 7.2). */
    for (level = 0; level <= NESTING_LEVELS; ++level) {
        snprintf(file_path, sizeof(file_path), "%sf.bin", dir_path);
        USBS_CHECK(usbs_ok(usbs_platform_write_file(file_path, "data", 4)));
        if (level < NESTING_LEVELS) {
            size_t len = strlen(dir_path);
            snprintf(dir_path + len, sizeof(dir_path) - len, "d\\");
            USBS_CHECK(usbs_ok(usbs_platform_make_dirs(dir_path)));
        }
    }

    make_device(&device, root);
    make_store(&store);

    USBS_CHECK(usbs_ok(usbs_scanner_scan(&device, &store, NULL, NULL, NULL, NULL, &result)));
    USBS_CHECK(result.status == USBS_SCAN_COMPLETED); /* depth cap is not an error */

    traversal = find_check(&result, "file_traversal");
    USBS_CHECK(traversal != NULL);
    USBS_CHECK(traversal->status == USBS_CHECK_RAN);
    /* Directories at depth 0..64 (65 of them) are opened and counted; depth
     * 65 onward (5 more levels, out of the 70 built) is refused, so exactly
     * 65 files are ever seen - not 71 (every level) and not fewer. */
    snprintf(expect_msg, sizeof(expect_msg), "%d file(s)", USBS_SCAN_MAX_DEPTH_UNDER_TEST + 1);
    USBS_CHECK(strstr(traversal->message, expect_msg) != NULL);

    usbs_scan_result_free(&result);
}

int main(void)
{
    test_invalid_args();
    test_basic_scan_completes();
    test_missing_root_is_a_failed_traversal();
    test_cancellation();
    test_progress_callback_fires();
#if defined(_WIN32)
    test_locked_files_do_not_affect_traversal();
#endif
    test_all_four_detectors_run_in_one_scan();
    test_deep_nesting_stops_at_scan_max_depth();
    return USBS_TEST_RESULT();
}
