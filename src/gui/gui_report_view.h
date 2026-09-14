/*
 * USB Sentinel - styled presentation of a scan result for the GUI.
 *
 * This is a *third formatter over the same usbs_scan_result_t*, alongside
 * usbs_report_build_json() and usbs_report_render_text() - never a second
 * source of truth (ARCHITECTURE.md section 7.4, and report.c's own note
 * above its text renderer). It exists because the other two cannot carry
 * styling: the GUI needs to colour a malicious finding red, and plain text
 * has nowhere to put that.
 *
 * Deliberately free of <windows.h>, HWNDs and any control handle - it emits
 * (style, UTF-8 text) runs through a callback and knows nothing about who
 * consumes them. gui_window.c turns those runs into RichEdit CHARFORMAT2W
 * runs; tests/test_gui_report_view.c collects them into a buffer. Same
 * "pure core, thin platform wrapper" split as gui_worker.c (section 14.3)
 * and usbs_hash_match_lookup() (section 11.3).
 *
 * Module-internal, like gui_worker.h: not part of the cross-module surface
 * in include/usbsentinel/.
 */
#ifndef USBS_GUI_REPORT_VIEW_H
#define USBS_GUI_REPORT_VIEW_H

#include "usbsentinel/scan.h"
#include "usbsentinel/types.h"

/*
 * Semantic styles, not colours. gui_window.c owns the palette; this module
 * only says what a run *means*, so the two can be changed independently
 * and so the meaning is what tests assert on.
 */
typedef enum gui_text_style {
    GUI_STYLE_TITLE = 0, /* the report's one top-level heading */
    GUI_STYLE_SECTION,   /* "DEVICE", "SCAN", "CHECKS PERFORMED" */
    GUI_STYLE_LABEL,     /* the left-hand label of a labelled value */
    GUI_STYLE_BODY,      /* ordinary value text */
    GUI_STYLE_MUTED,     /* secondary detail: paths, reasons, disclaimers */
    GUI_STYLE_GOOD,      /* an affirmatively clean result */
    GUI_STYLE_WARNING,   /* suspicious, skipped, failed, incomplete */
    GUI_STYLE_THREAT,    /* a high-severity finding: the loudest style */
    GUI_STYLE_COUNT
} gui_text_style_t;

/*
 * The headline verdict.
 *
 * CLEAN is deliberately hard to earn: the scan must have completed AND
 * every check must have run AND nothing above INFO severity may have been
 * found. A cancelled scan, a disconnected device or a failed check yields
 * INCOMPLETE instead - reporting green over a scan that did not finish is
 * exactly the silent capability gap ARCHITECTURE.md section 7.3 forbids,
 * and it is worse in a GUI than in a text report because a colour is read
 * at a glance and believed.
 */
typedef enum gui_verdict {
    GUI_VERDICT_CLEAN = 0,  /* completed, everything ran, nothing found */
    GUI_VERDICT_INCOMPLETE, /* nothing found, but the scan cannot vouch for that */
    GUI_VERDICT_SUSPICIOUS, /* warning-severity findings, nothing high */
    GUI_VERDICT_THREAT      /* at least one high-severity finding */
} gui_verdict_t;

typedef struct gui_report_summary {
    gui_verdict_t verdict;

    size_t high_count;
    size_t warning_count;
    size_t info_count;
    size_t finding_count;

    size_t checks_run;
    size_t checks_skipped;
    size_t checks_failed;

    usbs_bool completed; /* result->status == USBS_SCAN_COMPLETED */
    usbs_u64  paths_skipped; /* result->paths_skipped (Phase 17) */
} gui_report_summary_t;

/* NULL-safe on both arguments; a NULL result yields a zeroed summary whose
 * verdict is INCOMPLETE (never CLEAN - "no data" is not "nothing wrong"). */
void gui_report_summarize(const usbs_scan_result_t *result,
                          gui_report_summary_t      *out_summary);

/* Short, all-caps banner text, e.g. "THREATS DETECTED". Never NULL. */
const char *gui_verdict_headline(gui_verdict_t verdict);

/* One sentence of supporting detail for the banner, written into `buf`.
 * Returns `buf` for convenient inline use. */
const char *gui_verdict_detail(const gui_report_summary_t *summary,
                               char                       *buf,
                               size_t                      cap);

/* The style a run of the verdict's own text should use. */
gui_text_style_t gui_verdict_style(gui_verdict_t verdict);

/*
 * Human-readable name for a check id ("autorun_inspection" ->
 * "Autorun inspection"). Returns `id` itself for an id this function does
 * not know, so a detector added later degrades to its raw id rather than
 * disappearing from the report. Never NULL for a non-NULL `id`.
 */
const char *gui_check_display_name(const char *id);

/*
 * Total counts for the run, when the caller knows them. The scan result
 * does not carry these (the engine records them inside file_traversal's
 * own message), so this stays optional: pass NULL and the corresponding
 * line is simply omitted rather than guessed at.
 */
typedef struct gui_report_totals {
    usbs_u64 files;
    usbs_u64 bytes;
} gui_report_totals_t;

/*
 * Emits one contiguous run of text in one style. `utf8_text` is
 * NUL-terminated, may contain "\r\n", and is only valid for the duration
 * of the call - a consumer that needs to keep it must copy it.
 */
typedef void (*gui_text_emit_fn)(void *ctx, gui_text_style_t style, const char *utf8_text);

/*
 * Renders `result` as a sequence of styled runs. Emits nothing when
 * `result` or `emit` is NULL. `totals` may be NULL (see above).
 */
void gui_report_render_runs(const usbs_scan_result_t  *result,
                            const gui_report_totals_t *totals,
                            gui_text_emit_fn           emit,
                            void                      *ctx);

#endif /* USBS_GUI_REPORT_VIEW_H */
