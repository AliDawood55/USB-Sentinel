/*
 * USB Sentinel - detector registry.
 *
 * A fixed, statically-compiled array of checks - deliberately not a plugin
 * system or dynamic-loading mechanism (ARCHITECTURE.md's Phase 3 decision:
 * "do not over-design a plugin system"). Adding a detector means adding one
 * entry to the array in registry.c, nothing more.
 *
 * Detectors inspect; they do not enumerate devices, probe capabilities, or
 * persist anything - all of that is handed to them read-only through
 * usbs_detect_context_t (and, for per-file detectors, usbs_detector_file_ctx_t)
 * by whoever runs them (scanner).
 *
 * Two detector shapes, per ARCHITECTURE.md's Phase 5 notes:
 *
 *   - `run`: a whole-check detector invoked once, responsible for its own
 *     targeted access (autorun.inf: one fixed path, O(1), no walk needed).
 *   - `on_file`: a per-file detector invoked once per file during scanner's
 *     single shared walk (suspicious_filename, lnk_inspection, hash_match) -
 *     these used to each walk the volume independently; Phase 5 consolidated
 *     that into one walk scanner owns, dispatching to every on_file detector
 *     per entry.
 *
 * A detector sets exactly one of the two - nothing enforces this at runtime
 * (that would be machinery for a case that does not arise among Phase 5's
 * four detectors); if a detector ever genuinely needs both, revisit then.
 */
#ifndef USBSENTINEL_DETECTOR_H
#define USBSENTINEL_DETECTOR_H

#include "usbsentinel/platform.h"
#include "usbsentinel/scan.h"

typedef struct usbs_detect_context {
    const usbs_device_t       *device;
    const char                *volume_path; /* UTF-8 "\\?\Volume{guid}\", trailing separator */
    const usbs_capabilities_t *capabilities;
} usbs_detect_context_t;

/*
 * Runs one check. Implementations call usbs_check_result_init(out_result, id)
 * first (id must match the detector's own usbs_detector_t.id), then either
 * leave it USBS_CHECK_RAN and push findings, or call
 * usbs_check_result_set_skipped()/_set_failed(). The return value is reserved
 * for a detector that cannot even attempt the check (e.g. bad arguments);
 * an inspected-but-negative result is USBS_OK with zero findings, not an
 * error.
 */
typedef usbs_status_t (*usbs_detector_fn)(const usbs_detect_context_t *ctx,
                                          usbs_check_result_t         *out_result);

/*
 * Context handed to an on_file callback: the same device/volume/capabilities
 * a run-style detector gets, plus this detector's own in-progress result
 * (already usbs_check_result_init()'d by scanner before the walk starts, and
 * pushed by scanner after it ends - the callback only ever appends findings
 * to it, never replaces or frees it).
 */
typedef struct usbs_detector_file_ctx {
    const usbs_detect_context_t *detect_ctx;
    usbs_check_result_t         *result;
} usbs_detector_file_ctx_t;

/*
 * Called once per file during scanner's single shared walk (never for
 * directories). `full_path` and `entry` are only valid for the duration of
 * the call. The return value is intentionally not treated as fatal by the
 * caller: a per-file failure is this callback's own concern to isolate (log
 * it, skip it, return USBS_OK regardless) - one bad file must never abort
 * the walk for every other detector sharing it.
 */
typedef usbs_status_t (*usbs_detector_file_fn)(usbs_detector_file_ctx_t *ctx,
                                               const char               *full_path,
                                               const usbs_dir_entry_t   *entry);

typedef struct usbs_detector {
    const char             *id;
    const char             *description;
    usbs_detector_fn        run;      /* whole-check; NULL if this detector uses on_file */
    usbs_detector_file_fn   on_file;  /* per-file, walk-driven; NULL if this detector uses run */
} usbs_detector_t;

size_t                  usbs_detector_count(void);
const usbs_detector_t *usbs_detector_at(size_t index);

#endif /* USBSENTINEL_DETECTOR_H */
