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
#include "usbsentinel/path.h"
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
    snprintf(out, cap, "test_scanner_scratch_%08x" USBS_PATH_SEP, (unsigned)rand());
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
    snprintf(path, sizeof(path), "%ssub" USBS_PATH_SEP, root); usbs_platform_make_dirs(path);
    snprintf(path, sizeof(path), "%ssub" USBS_PATH_SEP "c.txt", root); usbs_platform_write_file(path, "x", 1);

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

    make_device(&device, "test_scanner_does_not_exist_at_all" USBS_PATH_SEP);
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

/* ------------------------------------------------------------------------ *
 * Phase 17 (ARCHITECTURE.md section 23.2): protected and vanishing
 * directories on a live volume are per-path skips, never the end of a scan.
 *
 * The "mock" access-denied directory is a real one, locked down with the
 * OS's own permissions (an empty protected DACL on Windows, mode 000 on
 * POSIX). A test double of usbs_platform_dir_open() would only prove the
 * walker reacts to a status code, not that fs_win32.c/fs_posix.c actually
 * produce that code for a directory the OS refuses, which is the half a
 * C:\System Volume Information scan depends on.
 * ------------------------------------------------------------------------ */

#if defined(_WIN32)
#include <sddl.h>

static usbs_bool set_directory_sddl(const char *utf8_path, const wchar_t *sddl)
{
    wchar_t              wide[400];
    PSECURITY_DESCRIPTOR sd = NULL;
    BOOL                 ok;

    MultiByteToWideChar(CP_UTF8, 0, utf8_path, -1, wide, (int)USBS_ARRAY_LEN(wide));
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL)) {
        return false;
    }
    ok = SetFileSecurityW(wide, DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd);
    return ok ? true : false;
}

/* "D:P" = a protected DACL with no entries: nobody is granted anything, and
 * nothing is inherited. The owner keeps the implicit right to change the
 * DACL again, which is what restore_directory() relies on. Elevation does
 * not bypass it either: FindFirstFileW does not use backup semantics. */
static usbs_bool deny_directory(const char *path)  { return set_directory_sddl(path, L"D:P"); }
static void      restore_directory(const char *path) { set_directory_sddl(path, L"D:(A;OICI;FA;;;WD)"); }
#else
#include <sys/stat.h>
#include <unistd.h>

static usbs_bool deny_directory(const char *path)  { return chmod(path, 0) == 0; }
static void      restore_directory(const char *path) { (void)chmod(path, 0755); }
#endif

static void test_access_denied_directory_is_skipped_not_fatal(void)
{
    char                root[260];
    char                path[400];
    char                locked[320];
    usbs_device_t       device;
    usbs_store_t        store;
    usbs_scan_result_t  result;
    usbs_dir_iter_t    *probe = NULL;
    const usbs_check_result_t *traversal;
    size_t              i;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));

    /* a.txt, locked/secret.txt (never counted), z_after/c.txt: a file on
     * each side of the denied directory, so the test also proves the walk
     * continued past it rather than stopping where it was refused. */
    snprintf(path, sizeof(path), "%sa.txt", root);
    usbs_platform_write_file(path, "hello", 5);
    snprintf(locked, sizeof(locked), "%slocked", root);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(locked)));
    snprintf(path, sizeof(path), "%s" USBS_PATH_SEP "secret.txt", locked);
    usbs_platform_write_file(path, "secret", 6);
    snprintf(path, sizeof(path), "%sz_after" USBS_PATH_SEP, root);
    usbs_platform_make_dirs(path);
    snprintf(path, sizeof(path), "%sz_after" USBS_PATH_SEP "c.txt", root);
    usbs_platform_write_file(path, "x", 1);

    USBS_CHECK(deny_directory(locked));

    /* Running as root on POSIX (a Docker container) ignores mode 000, so
     * there is no denial to observe; the assertions below would then be
     * testing nothing. Checked, not assumed. */
    if (usbs_ok(usbs_platform_dir_open(locked, &probe))) {
        usbs_platform_dir_close(probe);
        restore_directory(locked);
        printf("test_access_denied_directory_is_skipped_not_fatal: "
               "directory permissions not enforced for this user; skipped\n");
        return;
    }
    USBS_CHECK(usbs_platform_dir_open(locked, &probe) == USBS_ERR_ACCESS_DENIED);

    make_device(&device, root);
    make_store(&store);

    USBS_CHECK(usbs_ok(usbs_scanner_scan(&device, &store, NULL, NULL, NULL, NULL, &result)));

    /* The pre-Phase-17 walker reported this as USBS_SCAN_ABORTED, "device
     * disconnected", with every detector skipped. */
    USBS_CHECK(result.status == USBS_SCAN_COMPLETED);
    USBS_CHECK(result.paths_skipped == 1);

    traversal = find_check(&result, "file_traversal");
    USBS_CHECK(traversal != NULL);
    USBS_CHECK(traversal->status == USBS_CHECK_RAN);
    USBS_CHECK(strstr(traversal->message, "completed") != NULL);
    USBS_CHECK(strstr(traversal->message, "2 file(s)") != NULL);
    USBS_CHECK(strstr(traversal->message, "1 location(s) skipped") != NULL);

    /* A skip is a coverage note, not an incomplete scan: every detector ran. */
    for (i = 0; i < result.checks.count; ++i) {
        USBS_CHECK(result.checks.items[i].status == USBS_CHECK_RAN);
    }

    usbs_scan_result_free(&result);
    restore_directory(locked);
}

#if defined(_WIN32)
/*
 * A directory deleted by someone else between being listed and being
 * entered is routine on a live system volume (a temp folder, a browser
 * cache). It is skipped when the volume root is still reachable, and is
 * never read as "device removed".
 *
 * The deletion happens from inside the scan itself, in the progress
 * callback for a.txt. NTFS lists a directory in name order and
 * FindFirstFileW fetches this three-entry listing in one batch, so
 * "b_vanishing" has already been listed but not yet entered when the
 * callback removes it. That ordering is what makes this deterministic, and
 * why the test is Windows-only (readdir() order on POSIX is unspecified).
 */
typedef struct vanish_ctx {
    char      dir[320];
    char      file[400];
    usbs_bool done;
} vanish_ctx_t;

static void vanish_on_first_file(void *ctx, const usbs_scan_progress_t *progress)
{
    vanish_ctx_t *v = (vanish_ctx_t *)ctx;
    wchar_t       wide[400];

    USBS_UNUSED(progress);
    if (v->done) {
        return;
    }
    v->done = true;
    MultiByteToWideChar(CP_UTF8, 0, v->file, -1, wide, (int)USBS_ARRAY_LEN(wide));
    USBS_CHECK(DeleteFileW(wide));
    MultiByteToWideChar(CP_UTF8, 0, v->dir, -1, wide, (int)USBS_ARRAY_LEN(wide));
    USBS_CHECK(RemoveDirectoryW(wide));
}

static void test_directory_vanishing_mid_scan_is_not_device_removal(void)
{
    char                root[260];
    char                path[400];
    vanish_ctx_t        vanish;
    usbs_device_t       device;
    usbs_store_t        store;
    usbs_scan_result_t  result;
    const usbs_check_result_t *traversal;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));

    memset(&vanish, 0, sizeof(vanish));
    snprintf(path, sizeof(path), "%sa.txt", root);
    usbs_platform_write_file(path, "hello", 5);
    snprintf(vanish.dir, sizeof(vanish.dir), "%sb_vanishing", root);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(vanish.dir)));
    snprintf(vanish.file, sizeof(vanish.file), "%s" USBS_PATH_SEP "inner.txt", vanish.dir);
    usbs_platform_write_file(vanish.file, "inner", 5);
    snprintf(path, sizeof(path), "%sc.txt", root);
    usbs_platform_write_file(path, "x", 1);

    make_device(&device, root);
    make_store(&store);

    USBS_CHECK(usbs_ok(usbs_scanner_scan(&device, &store, NULL, NULL,
                                         vanish_on_first_file, &vanish, &result)));
    USBS_CHECK(vanish.done);
    USBS_CHECK(result.status == USBS_SCAN_COMPLETED);
    USBS_CHECK(result.paths_skipped == 1);

    traversal = find_check(&result, "file_traversal");
    USBS_CHECK(traversal != NULL);
    USBS_CHECK(strstr(traversal->message, "completed") != NULL);
    USBS_CHECK(strstr(traversal->message, "device disconnected") == NULL);
    USBS_CHECK(strstr(traversal->message, "2 file(s)") != NULL); /* a.txt, c.txt */

    usbs_scan_result_free(&result);
}
#endif /* _WIN32 */

/*
 * The other half of the classification: when the scan root itself has
 * gone, a failure below it still means the device was removed, exactly as
 * before Phase 17. The root is removed from inside the scan, so the
 * subdirectory the walk enters next fails and the root re-probe fails too.
 */
typedef struct remove_root_ctx {
    char      root[260];
    char      files[3][400]; /* room for sub + "/inner.txt" */
    char      sub[320];
    usbs_bool done;
} remove_root_ctx_t;

static void remove_everything_on_first_file(void *ctx, const usbs_scan_progress_t *progress)
{
    remove_root_ctx_t *r = (remove_root_ctx_t *)ctx;
    size_t             i;
    char               root_no_sep[260];

    USBS_UNUSED(progress);
    if (r->done) {
        return;
    }
    r->done = true;
    for (i = 0; i < USBS_ARRAY_LEN(r->files); ++i) {
        (void)remove(r->files[i]);
    }
    snprintf(root_no_sep, sizeof(root_no_sep), "%s", r->root);
    root_no_sep[strlen(root_no_sep) - 1] = '\0';
#if defined(_WIN32)
    {
        wchar_t wide[400];
        MultiByteToWideChar(CP_UTF8, 0, r->sub, -1, wide, (int)USBS_ARRAY_LEN(wide));
        RemoveDirectoryW(wide);
        MultiByteToWideChar(CP_UTF8, 0, root_no_sep, -1, wide, (int)USBS_ARRAY_LEN(wide));
        RemoveDirectoryW(wide);
    }
#else
    (void)rmdir(r->sub);
    (void)rmdir(root_no_sep);
#endif
}

static void test_failure_with_root_gone_is_still_device_removal(void)
{
    remove_root_ctx_t   ctx;
    usbs_device_t       device;
    usbs_store_t        store;
    usbs_scan_result_t  result;
    const usbs_check_result_t *traversal;

    memset(&ctx, 0, sizeof(ctx));
    make_scratch_root(ctx.root, sizeof(ctx.root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(ctx.root)));
    snprintf(ctx.files[0], sizeof(ctx.files[0]), "%sa.txt", ctx.root);
    usbs_platform_write_file(ctx.files[0], "hello", 5);
    snprintf(ctx.sub, sizeof(ctx.sub), "%sb_sub", ctx.root);
    usbs_platform_make_dirs(ctx.sub);
    snprintf(ctx.files[1], sizeof(ctx.files[1]), "%s" USBS_PATH_SEP "inner.txt", ctx.sub);
    usbs_platform_write_file(ctx.files[1], "inner", 5);
    snprintf(ctx.files[2], sizeof(ctx.files[2]), "%sc.txt", ctx.root);
    usbs_platform_write_file(ctx.files[2], "x", 1);

    make_device(&device, ctx.root);
    make_store(&store);

    USBS_CHECK(usbs_ok(usbs_scanner_scan(&device, &store, NULL, NULL,
                                         remove_everything_on_first_file, &ctx, &result)));
    USBS_CHECK(ctx.done);

#if defined(_WIN32)
    /* Same name-ordered, single-batch listing as the vanishing test above:
     * b_sub is entered after the root is gone, so this is deterministic. */
    USBS_CHECK(result.status == USBS_SCAN_ABORTED);
    traversal = find_check(&result, "file_traversal");
    USBS_CHECK(traversal != NULL);
    USBS_CHECK(strstr(traversal->message, "device disconnected") != NULL);
    USBS_CHECK(result.paths_skipped == 0);
#else
    /* readdir() order is unspecified: b_sub may have been walked before the
     * first file's callback removed anything. Either way a removed root must
     * never be reported as a skip. */
    traversal = find_check(&result, "file_traversal");
    USBS_CHECK(traversal != NULL);
    USBS_CHECK(result.paths_skipped == 0);
#endif

    usbs_scan_result_free(&result);
}

/*
 * Phase 17.1 (ARCHITECTURE.md section 24): the internal-drive location
 * policy, end to end through the real walk. The same tree is scanned as an
 * internal NVMe volume and as a USB stick:
 *
 *   build/x64/tests/test_scanner_scratch_0badc0de/invoice.pdf.exe  (fixture)
 *   Users/alida/AppData/Roaming/Microsoft/Windows/Recent/CV_ALI.pdf.lnk
 *   Projects/app/node_modules/pkg/Iterator.zip.js
 *
 * Internal: the fixture tree is excluded (and counted), the Recent Items
 * name is not reported (counted), and Iterator.zip.js is INFO (counted as
 * lowered), all stated in the checks' messages. USB: none of that, and all
 * three are HIGH.
 */
static void build_policy_tree(const char *root)
{
    char path[600];

    snprintf(path, sizeof(path), "%sbuild" USBS_PATH_SEP "x64" USBS_PATH_SEP "tests" USBS_PATH_SEP
             "test_scanner_scratch_0badc0de" USBS_PATH_SEP, root);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(path)));
    snprintf(path + strlen(path), sizeof(path) - strlen(path), "invoice.pdf.exe");
    usbs_platform_write_file(path, "x", 1);

    snprintf(path, sizeof(path), "%sUsers" USBS_PATH_SEP "alida" USBS_PATH_SEP "AppData" USBS_PATH_SEP
             "Roaming" USBS_PATH_SEP "Microsoft" USBS_PATH_SEP "Windows" USBS_PATH_SEP "Recent" USBS_PATH_SEP,
             root);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(path)));
    snprintf(path + strlen(path), sizeof(path) - strlen(path), "CV_ALI.pdf.lnk");
    usbs_platform_write_file(path, "not a real shortcut", 19);

    snprintf(path, sizeof(path), "%sProjects" USBS_PATH_SEP "app" USBS_PATH_SEP "node_modules"
             USBS_PATH_SEP "pkg" USBS_PATH_SEP, root);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(path)));
    snprintf(path + strlen(path), sizeof(path) - strlen(path), "Iterator.zip.js");
    usbs_platform_write_file(path, "module.exports = 1;", 19);
}

static void test_internal_drive_location_policy_end_to_end(void)
{
    char                root[260];
    usbs_device_t       device;
    usbs_store_t        store;
    usbs_scan_result_t  result;
    const usbs_check_result_t *traversal;
    const usbs_check_result_t *suspicious;
    size_t              i;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    build_policy_tree(root);
    make_store(&store);

    /* --- internal NVMe volume --- */
    make_device(&device, root);
    device.bus_type   = USBS_BUS_NVME;
    device.usb_vid[0] = '\0';
    device.usb_pid[0] = '\0';

    USBS_CHECK(usbs_ok(usbs_scanner_scan(&device, &store, NULL, NULL, NULL, NULL, &result)));
    USBS_CHECK(result.status == USBS_SCAN_COMPLETED);
    USBS_CHECK(result.paths_excluded == 1);

    traversal = find_check(&result, "file_traversal");
    USBS_CHECK(traversal != NULL);
    USBS_CHECK(strstr(traversal->message, "2 file(s)") != NULL); /* fixture file not walked */
    USBS_CHECK(strstr(traversal->message, "1 location(s) excluded (USB Sentinel test fixtures)") != NULL);

    suspicious = find_check(&result, "suspicious_filename");
    USBS_CHECK(suspicious != NULL);
    if (suspicious != NULL) {
        USBS_CHECK(suspicious->status == USBS_CHECK_RAN);
        USBS_CHECK(suspicious->findings.count == 1);
        if (suspicious->findings.count == 1) {
            USBS_CHECK(suspicious->findings.items[0].severity == USBS_SEVERITY_INFO);
            USBS_CHECK(strstr(suspicious->findings.items[0].path, "node_modules") != NULL);
        }
        USBS_CHECK(strstr(suspicious->message,
                          "internal-drive location policy: 1 match(es) in OS-generated or dependency "
                          "locations not reported, 1 reported at lowered severity") != NULL);
    }
    usbs_scan_result_free(&result);

    /* --- the same tree as a USB stick: strict rules, nothing excluded --- */
    make_device(&device, root);
    USBS_CHECK(usbs_ok(usbs_scanner_scan(&device, &store, NULL, NULL, NULL, NULL, &result)));
    USBS_CHECK(result.paths_excluded == 0);

    traversal = find_check(&result, "file_traversal");
    USBS_CHECK(traversal != NULL && strstr(traversal->message, "3 file(s)") != NULL);
    USBS_CHECK(traversal != NULL && strstr(traversal->message, "excluded") == NULL);

    suspicious = find_check(&result, "suspicious_filename");
    USBS_CHECK(suspicious != NULL);
    if (suspicious != NULL) {
        USBS_CHECK(suspicious->findings.count == 3);
        for (i = 0; i < suspicious->findings.count; ++i) {
            USBS_CHECK(suspicious->findings.items[i].severity == USBS_SEVERITY_HIGH);
        }
        USBS_CHECK(strstr(suspicious->message, "location policy") == NULL);
    }
    usbs_scan_result_free(&result);
}

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
            snprintf(dir_path + len, sizeof(dir_path) - len, "d" USBS_PATH_SEP);
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
    test_access_denied_directory_is_skipped_not_fatal();
#if defined(_WIN32)
    test_directory_vanishing_mid_scan_is_not_device_removal();
#endif
    test_failure_with_root_gone_is_still_device_removal();
    test_internal_drive_location_policy_end_to_end();
    return USBS_TEST_RESULT();
}
