#include "usbsentinel/scanner.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "usbsentinel/detector.h"
#include "usbsentinel/log.h"
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

    usbs_u64  file_count;
    usbs_u64  byte_count;

    usbs_bool cancelled;
    usbs_bool device_removed;

    const usbs_detect_context_t *detect_ctx; /* handed to every on_file callback */
    on_file_slot_t               *slots;      /* one per registered on_file detector */
    size_t                         slot_count;
} traverse_state_t;

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
        /* A subdirectory that existed moments ago is now gone - the most
         * likely explanation is the device was removed mid-scan. */
        USBS_LOG_W("cannot open %s: %s (treating as device removed)",
                  dir_path, usbs_status_string(status));
        state->device_removed = true;
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
        int              written;

        if (state->cancel_check != NULL && state->cancel_check(state->cancel_ctx)) {
            state->cancelled = true;
            break;
        }

        status = usbs_platform_dir_next(iter, &entry);
        if (status == USBS_ERR_NOT_FOUND) {
            break; /* normal end of this directory's listing */
        }
        if (!usbs_ok(status)) {
            USBS_LOG_W("directory listing failed for %s: %s",
                      dir_path, usbs_status_string(status));
            state->device_removed = true;
            break;
        }

        /* Never follow a reparse point (junction/symlink), file or
         * directory: it may point outside the volume being scanned, and for
         * a directory it is the classic traversal-loop hazard. */
        if (entry.is_reparse_point) {
            USBS_LOG_D("skipping reparse point: %s\\%s", dir_path, entry.name);
            continue;
        }

        written = snprintf(child_path, sizeof(child_path), "%s\\%s", dir_path, entry.name);
        if (written < 0 || (size_t)written >= sizeof(child_path)) {
            USBS_LOG_W("path too long, skipping an entry under %s", dir_path);
            continue;
        }

        if (entry.is_directory) {
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

    usbs_check_result_init(&traversal_check, "file_traversal");
    walk_status = walk_dir(device->volume_path, 0, &state);

    if (!usbs_ok(walk_status)) {
        usbs_check_result_set_failed(&traversal_check, usbs_status_string(walk_status));
    } else {
        const char *outcome = state.cancelled       ? "cancelled"
                             : state.device_removed  ? "device disconnected"
                                                      : "completed";
        snprintf(traversal_check.message, sizeof(traversal_check.message),
                "%s: %llu file(s), %llu byte(s)", outcome,
                (unsigned long long)state.file_count,
                (unsigned long long)state.byte_count);
    }
    usbs_check_list_push(&out_result->checks, &traversal_check);

    incomplete = !usbs_ok(walk_status) || state.cancelled || state.device_removed;

    if (!incomplete) {
        run_whole_check_detectors(&detect_ctx, &out_result->checks);
        for (i = 0; i < slot_count; ++i) {
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
