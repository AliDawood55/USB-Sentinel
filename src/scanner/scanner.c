#include "usbsentinel/scanner.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "usbsentinel/detector.h"
#include "usbsentinel/location.h"
#include "usbsentinel/log.h"
#include "usbsentinel/path.h"
#include "usbsentinel/platform.h"

#define USBS_SCAN_MAX_DEPTH 64

/* ------------------------------------------------------------------------ *
 * Traversal
 *
 * A single walk, owned here, serves two purposes at once:
 *   - metadata-only counting for the "file_traversal" check (counts come
 *     from usbs_dir_entry_t.size_bytes; no file is ever opened for this)
 *   - dispatching every file entry to every registered on_file detector
 *     (ARCHITECTURE.md's Phase 5 notes: this used to be three separate
 *     walks - one here, one each inside suspicious_filename and
 *     lnk_inspect - consolidated once a second and third real on_file
 *     consumer existed, the same "wait for the real need" discipline this
 *     project has applied every phase).
 * ------------------------------------------------------------------------ */

typedef struct on_file_slot {
    const usbs_detector_t *detector;
    usbs_check_result_t    result;
} on_file_slot_t;

typedef struct traverse_state {
    usbs_cancel_check_fn cancel_check;
    void                 *cancel_ctx;

    usbs_progress_fn on_progress;
    void            *progress_ctx;

    const char *root_path; /* the volume root, re-probed by classify_path_failure() */

    usbs_u64  file_count;
    usbs_u64  byte_count;
    usbs_u64  paths_skipped;
    usbs_u64  paths_excluded;   /* Phase 17.1: self-test fixture trees not descended into */
    usbs_bool location_policy;  /* usbs_location_policy_applies(device), computed once */

    usbs_bool cancelled;
    usbs_bool device_removed;

    const usbs_detect_context_t *detect_ctx; /* handed to every on_file callback */
    on_file_slot_t               *slots;      /* one per registered on_file detector */
    size_t                         slot_count;
} traverse_state_t;

static usbs_bool root_still_reachable(const traverse_state_t *state)
{
    usbs_dir_iter_t *probe = NULL;

    if (!usbs_ok(usbs_platform_dir_open(state->root_path, &probe))) {
        return false;
    }
    usbs_platform_dir_close(probe);
    return true;
}

/*
 * Decides what a failure to open or list one directory *below* the root
 * means (Phase 17, ARCHITECTURE.md section 23.2).
 *
 * Before Phase 17 every such failure meant "device removed". That was a
 * fair reading of a USB stick, which has no protected directories and no
 * other process churning its contents. It is wrong on a live system
 * volume. C:\System Volume Information alone would have ended a scan of C:
 * in its first second and reported every detector as skipped, and so would
 * any temp directory another process deleted while the walk was on its way
 * to it.
 *
 * So every such failure, access denied included, re-probes the scan root.
 * If the root still opens, this one path was refused, vanished or failed on
 * a live volume, and it is skipped. If the root is gone too, the device
 * really was removed, which keeps the original behaviour for a stick
 * pulled mid-scan. The probe costs one extra open, and only on a path that
 * has already failed.
 *
 * Access denied is deliberately not trusted to mean "the volume is still
 * there". Windows reports a delete-pending directory as ERROR_ACCESS_DENIED
 * (STATUS_DELETE_PENDING), and that is exactly what a scan root looks like
 * while it is being torn down under an open find handle. Found by
 * test_failure_with_root_gone_is_still_device_removal.
 *
 * A skip is never silent. It is logged, counted in paths_skipped, and that
 * count reaches every report format through file_traversal's message.
 */
static void classify_path_failure(traverse_state_t *state, const char *path,
                                  const char *what, usbs_status_t status)
{
    if (root_still_reachable(state)) {
        ++state->paths_skipped;
        USBS_LOG_I("skipped (%s: %s): %s", what, usbs_status_string(status), path);
        return;
    }
    USBS_LOG_W("%s failed for %s: %s, and the volume root is no longer reachable "
               "(treating as device removed)", what, path, usbs_status_string(status));
    state->device_removed = true;
}

static usbs_status_t walk_dir(const char *dir_path, int depth, traverse_state_t *state)
{
    usbs_dir_iter_t *iter;
    usbs_status_t    status;

    if (state->cancelled || state->device_removed) {
        return USBS_OK;
    }
    if (depth > USBS_SCAN_MAX_DEPTH) {
        USBS_LOG_W("max traversal depth reached, not descending into %s", dir_path);
        return USBS_OK;
    }

    status = usbs_platform_dir_open(dir_path, &iter);
    if (!usbs_ok(status)) {
        if (depth == 0) {
            /* The scan root itself is unreachable: a hard failure for the
             * whole scan, not something per-file isolation can absorb. */
            return status;
        }
        classify_path_failure(state, dir_path, "cannot open directory", status);
        return USBS_OK;
    }

    for (;;) {
        usbs_dir_entry_t entry;
        /* Phase 14: a volume path is now up to USBS_VOLUME_PATH_MAX and an
         * entry name up to USBS_NAME_MAX, so 1024 no longer covers even one
         * level of nesting in the worst case. Over-long paths are still
         * skipped with a warning rather than truncated, but that should mean
         * "genuinely absurd", not "a long name near the volume root". Sized
         * against USBS_SCAN_MAX_DEPTH: this buffer is per recursion frame. */
        char             child_path[2048];

        if (state->cancel_check != NULL && state->cancel_check(state->cancel_ctx)) {
            state->cancelled = true;
            break;
        }

        status = usbs_platform_dir_next(iter, &entry);
        if (status == USBS_ERR_NOT_FOUND) {
            break; /* normal end of this directory's listing */
        }
        if (!usbs_ok(status)) {
            /* Whatever this directory listed before the failure has already
             * been walked; the rest of it is what gets skipped. At depth 0
             * that is the rest of the root, and the root re-probe then
             * decides, exactly as for a subdirectory. */
            classify_path_failure(state, dir_path, "directory listing", status);
            break;
        }

        /* Never follow a reparse point (junction/symlink), file or
         * directory: it may point outside the volume being scanned, and for
         * a directory it is the classic traversal-loop hazard. */
        if (entry.is_reparse_point) {
            USBS_LOG_D("skipping reparse point: %s%s%s", dir_path,
                       USBS_PATH_SEP, entry.name);
            continue;
        }

        if (!usbs_ok(usbs_path_join(child_path, sizeof(child_path), dir_path,
                                    entry.name))) {
            USBS_LOG_W("path too long, skipping an entry under %s", dir_path);
            continue;
        }

        if (entry.is_directory) {
            /* Phase 17.1 (ARCHITECTURE.md section 24.4): on an internal
             * drive, this project's own test scratch trees are the one
             * location not examined at all. Their disguised names and
             * malformed shortcuts are deliberate fixtures, and there were
             * about 360 findings' worth of them on the development machine. The
             * match is narrow (location.h) and counted, never silent. */
            if (state->location_policy &&
                usbs_location_classify(usbs_location_relative(state->root_path, child_path)) ==
                    USBS_LOCATION_SELF_TEST_FIXTURES) {
                ++state->paths_excluded;
                /* DEBUG, not INFO like a skip: a developer machine
                 * accumulates thousands of these (2155 on the Phase 17.1
                 * verification drive), and unlike a refused path they are
                 * an expected, already-counted policy outcome. */
                USBS_LOG_D("excluded (%s): %s",
                           usbs_location_kind_string(USBS_LOCATION_SELF_TEST_FIXTURES), child_path);
                continue;
            }
            status = walk_dir(child_path, depth + 1, state);
            if (!usbs_ok(status)) {
                return status; /* only the root-open case reaches here */
            }
            if (state->cancelled || state->device_removed) {
                break;
            }
            continue;
        }

        /* Metadata only: size_bytes already came from the directory listing
         * itself, so counting a file costs no I/O beyond that listing. */
        ++state->file_count;
        state->byte_count += entry.size_bytes;

        if (state->on_progress != NULL) {
            usbs_scan_progress_t progress;
            progress.files_scanned = state->file_count;
            progress.bytes_scanned = state->byte_count;
            progress.paths_skipped = state->paths_skipped;
            state->on_progress(state->progress_ctx, &progress);
        }

        /* One walk, every on_file detector - see the module comment above.
         * A callback's own per-file failure is its concern to isolate
         * (usbsentinel/detector.h); its return value is not treated as
         * fatal here. */
        {
            size_t i;
            for (i = 0; i < state->slot_count; ++i) {
                usbs_detector_file_ctx_t file_ctx;
                file_ctx.detect_ctx = state->detect_ctx;
                file_ctx.result     = &state->slots[i].result;
                (void)state->slots[i].detector->on_file(&file_ctx, child_path, &entry);
            }
        }
    }

    usbs_platform_dir_close(iter);
    return USBS_OK;
}

/* ------------------------------------------------------------------------ *
 * Identifiers and timestamps
 * ------------------------------------------------------------------------ */

/* Not cryptographically random: scan_id only needs to be reasonably unique
 * as a filename/report identifier, not to resist prediction. */
static void generate_scan_id(char *out, size_t cap)
{
    static usbs_bool seeded = false;
    unsigned         r1, r2, r3, r4;

    if (!seeded) {
        srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)out);
        seeded = true;
    }

    r1 = (unsigned)rand() & 0xFFFFu;
    r2 = (unsigned)rand() & 0xFFFFu;
    r3 = (unsigned)rand() & 0xFFFFu;
    r4 = (unsigned)rand() & 0xFFFFu;
    snprintf(out, cap, "%04x%04x%04x%04x", r1, r2, r3, r4);
}

static void now_utc_iso8601(char *out, size_t cap)
{
    time_t    now = time(NULL);
    struct tm tm_now;
    usbs_bool ok;

#if defined(_MSC_VER)
    ok = (gmtime_s(&tm_now, &now) == 0);
#else
    ok = (gmtime_r(&now, &tm_now) != NULL);
#endif

    if (!ok || strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm_now) == 0) {
        snprintf(out, cap, "1970-01-01T00:00:00Z");
    }
}

/* ------------------------------------------------------------------------ *
 * Orchestration
 * ------------------------------------------------------------------------ */

/* Runs every whole-check detector (run != NULL) - unaffected by the shared
 * walk; on_file detectors are handled separately by the caller. */
static void run_whole_check_detectors(const usbs_detect_context_t *ctx,
                                      usbs_check_list_t           *checks)
{
    size_t count = usbs_detector_count();
    size_t i;

    for (i = 0; i < count; ++i) {
        const usbs_detector_t *det = usbs_detector_at(i);
        usbs_check_result_t    result;

        if (det->run == NULL) {
            continue;
        }
        usbs_check_result_init(&result, det->id);
        det->run(ctx, &result);
        usbs_check_list_push(checks, &result);
    }
}

static void skip_whole_check_detectors(usbs_check_list_t *checks, const char *reason)
{
    size_t count = usbs_detector_count();
    size_t i;

    for (i = 0; i < count; ++i) {
        const usbs_detector_t *det = usbs_detector_at(i);
        usbs_check_result_t    result;

        if (det->run == NULL) {
            continue;
        }
        usbs_check_result_init(&result, det->id);
        usbs_check_result_set_skipped(&result, reason);
        usbs_check_list_push(checks, &result);
    }
}

/*
 * Phase 17.1 (ARCHITECTURE.md section 24.5): states in a check's own message
 * what the internal-drive location policy did to its findings, so the tuning
 * reaches JSON, CSV, text and the GUI without a schema change. Detectors
 * only count; the sentence is written once, here. Appended after any message
 * the detector set itself, and a no-op when both counts are zero, so a USB
 * scan's report is unchanged.
 */
static void describe_location_policy(usbs_check_result_t *check)
{
    size_t len;

    if (check->policy_suppressed == 0 && check->policy_lowered == 0) {
        return;
    }
    len = strlen(check->message);
    if (len + 1 >= sizeof(check->message)) {
        return;
    }
    snprintf(check->message + len, sizeof(check->message) - len,
             "%sinternal-drive location policy: %llu match(es) in OS-generated or "
             "dependency locations not reported, %llu reported at lowered severity",
             len > 0 ? "; " : "",
             (unsigned long long)check->policy_suppressed,
             (unsigned long long)check->policy_lowered);
}

/* Allocates and initializes one slot per registered on_file detector.
 * *out_count may be 0 with *out_slots left NULL (nothing to free) if there
 * are none. */
static usbs_status_t prepare_on_file_slots(on_file_slot_t **out_slots, size_t *out_count)
{
    size_t          total = usbs_detector_count();
    size_t          i;
    size_t          used = 0;
    on_file_slot_t *slots;

    *out_slots = NULL;
    *out_count = 0;

    if (total == 0) {
        return USBS_OK;
    }

    slots = (on_file_slot_t *)calloc(total, sizeof(*slots));
    if (slots == NULL) {
        return USBS_ERR_NO_MEMORY;
    }

    for (i = 0; i < total; ++i) {
        const usbs_detector_t *det = usbs_detector_at(i);
        if (det->on_file == NULL) {
            continue;
        }
        slots[used].detector = det;
        usbs_check_result_init(&slots[used].result, det->id);
        ++used;
    }

    *out_slots = slots;
    *out_count = used;
    return USBS_OK;
}

usbs_status_t usbs_scanner_scan(const usbs_device_t *device,
                                const usbs_store_t   *store,
                                usbs_cancel_check_fn  cancel_check,
                                void                 *cancel_ctx,
                                usbs_progress_fn      on_progress,
                                void                 *progress_ctx,
                                usbs_scan_result_t   *out_result)
{
    traverse_state_t      state;
    usbs_check_result_t    traversal_check;
    usbs_status_t          walk_status;
    usbs_status_t          probe_status;
    char                   identity[USBS_IDENTITY_MAX];
    usbs_bool              incomplete;
    usbs_detect_context_t  detect_ctx;
    on_file_slot_t        *slots      = NULL;
    size_t                  slot_count = 0;
    size_t                  i;

    if (device == NULL || store == NULL || out_result == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    usbs_scan_result_init(out_result);
    out_result->device = *device;
    generate_scan_id(out_result->scan_id, sizeof(out_result->scan_id));
    now_utc_iso8601(out_result->started_at, sizeof(out_result->started_at));

    probe_status = usbs_platform_probe_capabilities(device, &out_result->capabilities);
    if (!usbs_ok(probe_status)) {
        /* Not fatal: capabilities simply stay at their zeroed (unavailable)
         * defaults, which is the conservative, honest default. */
        USBS_LOG_W("capability probe failed: %s", usbs_status_string(probe_status));
    }

    if (usbs_ok(usbs_device_identity(device, identity, sizeof(identity)))) {
        usbs_store_last_scan_t last;
        if (usbs_ok(usbs_store_last_scan(store, identity, &last)) && last.found) {
            USBS_LOG_I("previous scan of this device: %s (%zu report(s) on record)",
                      last.scanned_at, last.report_count);
        }
    }

    detect_ctx.device       = device;
    detect_ctx.volume_path  = device->volume_path;
    detect_ctx.capabilities = &out_result->capabilities;

    if (!usbs_ok(prepare_on_file_slots(&slots, &slot_count))) {
        USBS_LOG_W("could not allocate on_file detector slots; those checks will be skipped");
    }

    memset(&state, 0, sizeof(state));
    state.cancel_check  = cancel_check;
    state.cancel_ctx    = cancel_ctx;
    state.on_progress   = on_progress;
    state.progress_ctx  = progress_ctx;
    state.detect_ctx    = &detect_ctx;
    state.slots         = slots;
    state.slot_count    = slot_count;
    state.root_path       = device->volume_path;
    state.location_policy = usbs_location_policy_applies(device);

    usbs_check_result_init(&traversal_check, "file_traversal");
    walk_status = walk_dir(device->volume_path, 0, &state);
    out_result->paths_skipped  = state.paths_skipped;
    out_result->paths_excluded = state.paths_excluded;

    if (!usbs_ok(walk_status)) {
        usbs_check_result_set_failed(&traversal_check, usbs_status_string(walk_status));
    } else {
        const char *outcome = state.cancelled       ? "cancelled"
                             : state.device_removed  ? "device disconnected"
                                                      : "completed";
        int written = snprintf(traversal_check.message, sizeof(traversal_check.message),
                               "%s: %llu file(s), %llu byte(s)", outcome,
                               (unsigned long long)state.file_count,
                               (unsigned long long)state.byte_count);
        /* Appended only when non-zero, so a USB scan with nothing skipped
         * reports byte-for-byte what it always has. */
        if (state.paths_skipped > 0 && written > 0 &&
            (size_t)written < sizeof(traversal_check.message)) {
            written += snprintf(traversal_check.message + written,
                                sizeof(traversal_check.message) - (size_t)written,
                                ", %llu location(s) skipped (access denied or unavailable)",
                                (unsigned long long)state.paths_skipped);
        }
        if (state.paths_excluded > 0 && written > 0 &&
            (size_t)written < sizeof(traversal_check.message)) {
            snprintf(traversal_check.message + written,
                     sizeof(traversal_check.message) - (size_t)written,
                     ", %llu location(s) excluded (USB Sentinel test fixtures)",
                     (unsigned long long)state.paths_excluded);
        }
    }
    usbs_check_list_push(&out_result->checks, &traversal_check);

    incomplete = !usbs_ok(walk_status) || state.cancelled || state.device_removed;

    if (!incomplete) {
        run_whole_check_detectors(&detect_ctx, &out_result->checks);
        for (i = 0; i < slot_count; ++i) {
            describe_location_policy(&slots[i].result);
            usbs_check_list_push(&out_result->checks, &slots[i].result);
        }
    } else {
        const char *reason = !usbs_ok(walk_status) ? "volume could not be read"
                            : state.cancelled       ? "scan cancelled before this check ran"
                                                     : "device disconnected before this check ran";
        skip_whole_check_detectors(&out_result->checks, reason);
        /* Discard whatever partial findings an on_file detector collected
         * before the walk stopped early: an incomplete scan reports every
         * detector as skipped, never a partial "ran" - the same contract
         * whole-check detectors have always had (ARCHITECTURE.md section
         * 7.3: never simply absent, and never a misleadingly partial ran). */
        for (i = 0; i < slot_count; ++i) {
            usbs_check_result_free(&slots[i].result);
            usbs_check_result_init(&slots[i].result, slots[i].detector->id);
            usbs_check_result_set_skipped(&slots[i].result, reason);
            usbs_check_list_push(&out_result->checks, &slots[i].result);
        }
    }

    free(slots);

    now_utc_iso8601(out_result->finished_at, sizeof(out_result->finished_at));
    out_result->status = incomplete ? USBS_SCAN_ABORTED : USBS_SCAN_COMPLETED;

    return USBS_OK;
}
