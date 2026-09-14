/*
 * USB Sentinel - styled presentation of a scan result. See gui_report_view.h
 * for why this exists as a third formatter rather than a reuse of
 * usbs_report_render_text().
 *
 * Non-ASCII punctuation is written as explicit UTF-8 byte escapes rather
 * than as literal characters in this file. MSVC interprets a source file
 * with no BOM in the system ANSI code page, which would silently mangle
 * literal UTF-8 bullets into mojibake on a machine whose code page is not
 * 65001 - a defect that only shows up on someone else's machine. The bytes
 * are spelled out so no build flag or file encoding can change them.
 * Everything downstream already treats these strings as UTF-8 (gui_window.c
 * converts to UTF-16 at the Win32 boundary, exactly as fs_win32.c does).
 */
#include "gui_report_view.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "usbsentinel/device.h"

#define GUI_BULLET "\xE2\x80\xA2"     /* U+2022 BULLET */
#define GUI_MARKER "\xE2\x96\xB8"     /* U+25B8 BLACK RIGHT-POINTING SMALL TRIANGLE */
#define GUI_MIDDOT "\xC2\xB7"         /* U+00B7 MIDDLE DOT */

#define GUI_LINE_MAX 1024

/* Width of the label column in the DEVICE/SCAN sections. Wide enough for
 * the longest label below ("File system") plus breathing room. */
#define GUI_LABEL_WIDTH 13

/* ------------------------------------------------------------------------ *
 * Emit helpers
 * ------------------------------------------------------------------------ */

typedef struct emit_sink {
    gui_text_emit_fn fn;
    void            *ctx;
} emit_sink_t;

static void emit_text(const emit_sink_t *sink, gui_text_style_t style, const char *text)
{
    if (text != NULL && text[0] != '\0') {
        sink->fn(sink->ctx, style, text);
    }
}

static void emit_fmt(const emit_sink_t *sink, gui_text_style_t style, const char *fmt, ...)
{
    char    line[GUI_LINE_MAX];
    va_list args;

    va_start(args, fmt);
    vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);
    emit_text(sink, style, line);
}

/* A labelled value: grey label, then the value in its own style so a value
 * can be coloured independently of the row it sits on. */
static void emit_field(const emit_sink_t *sink, const char *label,
                       gui_text_style_t value_style, const char *value)
{
    emit_fmt(sink, GUI_STYLE_LABEL, "   " GUI_BULLET "  %-*s ", GUI_LABEL_WIDTH, label);
    emit_fmt(sink, value_style, "%s\r\n", (value != NULL && value[0] != '\0') ? value : "(not reported)");
}

static void emit_blank(const emit_sink_t *sink)
{
    emit_text(sink, GUI_STYLE_BODY, "\r\n");
}

static void emit_section(const emit_sink_t *sink, const char *title)
{
    emit_fmt(sink, GUI_STYLE_SECTION, "%s\r\n", title);
}

/* ------------------------------------------------------------------------ *
 * Small formatters
 * ------------------------------------------------------------------------ */

/* Mirrors report.c's format_size(), which is static to that translation
 * unit. Duplicated rather than exported: it is six lines, and widening
 * reporting's public header for it would be a worse trade than this
 * (ARCHITECTURE.md's "wait for a real second consumer" applies to
 * abstractions worth sharing, and a unit-suffix printer is not one). */
static void format_size(usbs_u64 bytes, char *buf, size_t cap)
{
    const char *units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    double      value   = (double)bytes;
    size_t      unit    = 0;

    while (value >= 1024.0 && unit + 1 < USBS_ARRAY_LEN(units)) {
        value /= 1024.0;
        ++unit;
    }
    if (unit == 0) {
        snprintf(buf, cap, "%llu B", (unsigned long long)bytes);
    } else {
        snprintf(buf, cap, "%.1f %s", value, units[unit]);
    }
}

static gui_text_style_t style_for_severity(usbs_severity_t severity)
{
    switch (severity) {
    case USBS_SEVERITY_HIGH:    return GUI_STYLE_THREAT;
    case USBS_SEVERITY_WARNING: return GUI_STYLE_WARNING;
    case USBS_SEVERITY_INFO:    break;
    }
    return GUI_STYLE_MUTED;
}

static const char *label_for_severity(usbs_severity_t severity)
{
    switch (severity) {
    case USBS_SEVERITY_HIGH:    return "HIGH";
    case USBS_SEVERITY_WARNING: return "SUSPICIOUS";
    case USBS_SEVERITY_INFO:    break;
    }
    return "INFO";
}

const char *gui_check_display_name(const char *id)
{
    if (id == NULL) {
        return "(unnamed check)";
    }
    if (strcmp(id, "file_traversal") == 0)      { return "File traversal"; }
    if (strcmp(id, "autorun_inspection") == 0)  { return "Autorun inspection"; }
    if (strcmp(id, "suspicious_filename") == 0) { return "Suspicious file names"; }
    if (strcmp(id, "lnk_inspection") == 0)      { return "Shortcut (.lnk) inspection"; }
    if (strcmp(id, "hash_match_example") == 0)  { return "Known-hash matching"; }
    /* An id this build does not know about still appears, under its own
     * name, rather than vanishing from the report. */
    return id;
}

/* ------------------------------------------------------------------------ *
 * Summary and verdict
 * ------------------------------------------------------------------------ */

void gui_report_summarize(const usbs_scan_result_t *result, gui_report_summary_t *out_summary)
{
    size_t i;

    if (out_summary == NULL) {
        return;
    }
    memset(out_summary, 0, sizeof(*out_summary));

    if (result == NULL) {
        /* No data is not the same as nothing wrong. */
        out_summary->verdict = GUI_VERDICT_INCOMPLETE;
        return;
    }

    out_summary->completed     = (result->status == USBS_SCAN_COMPLETED);
    out_summary->paths_skipped = result->paths_skipped;

    for (i = 0; i < result->checks.count; ++i) {
        const usbs_check_result_t *check = &result->checks.items[i];
        size_t                     j;

        switch (check->status) {
        case USBS_CHECK_RAN:     ++out_summary->checks_run;     break;
        case USBS_CHECK_SKIPPED: ++out_summary->checks_skipped; break;
        case USBS_CHECK_FAILED:  ++out_summary->checks_failed;  break;
        }

        for (j = 0; j < check->findings.count; ++j) {
            ++out_summary->finding_count;
            switch (check->findings.items[j].severity) {
            case USBS_SEVERITY_HIGH:    ++out_summary->high_count;    break;
            case USBS_SEVERITY_WARNING: ++out_summary->warning_count; break;
            case USBS_SEVERITY_INFO:    ++out_summary->info_count;    break;
            }
        }
    }

    /* Severity outranks completeness: a high-severity hit found before a
     * scan was cancelled is still a high-severity hit, and burying it
     * under "incomplete" would be the wrong thing to show loudest. */
    if (out_summary->high_count > 0) {
        out_summary->verdict = GUI_VERDICT_THREAT;
    } else if (out_summary->warning_count > 0) {
        out_summary->verdict = GUI_VERDICT_SUSPICIOUS;
    } else if (!out_summary->completed ||
               out_summary->checks_skipped > 0 ||
               out_summary->checks_failed > 0) {
        out_summary->verdict = GUI_VERDICT_INCOMPLETE;
    } else {
        out_summary->verdict = GUI_VERDICT_CLEAN;
    }
}

const char *gui_verdict_headline(gui_verdict_t verdict)
{
    switch (verdict) {
    case GUI_VERDICT_THREAT:     return "THREATS DETECTED";
    case GUI_VERDICT_SUSPICIOUS: return "SUSPICIOUS ITEMS FOUND";
    case GUI_VERDICT_INCOMPLETE: return "SCAN INCOMPLETE";
    case GUI_VERDICT_CLEAN:      break;
    }
    return "ALL CLEAR";
}

gui_text_style_t gui_verdict_style(gui_verdict_t verdict)
{
    switch (verdict) {
    case GUI_VERDICT_THREAT:     return GUI_STYLE_THREAT;
    case GUI_VERDICT_SUSPICIOUS: return GUI_STYLE_WARNING;
    case GUI_VERDICT_INCOMPLETE: return GUI_STYLE_WARNING;
    case GUI_VERDICT_CLEAN:      break;
    }
    return GUI_STYLE_GOOD;
}

const char *gui_verdict_detail(const gui_report_summary_t *summary, char *buf, size_t cap)
{
    if (buf == NULL || cap == 0) {
        return "";
    }
    if (summary == NULL) {
        snprintf(buf, cap, "No scan result available.");
        return buf;
    }

    switch (summary->verdict) {
    case GUI_VERDICT_THREAT:
        snprintf(buf, cap,
                 "%zu high-severity item(s) found on this device. Do not open them.",
                 summary->high_count);
        break;
    case GUI_VERDICT_SUSPICIOUS:
        snprintf(buf, cap,
                 "%zu item(s) worth a closer look. Nothing matched a known-malicious signature.",
                 summary->warning_count);
        break;
    case GUI_VERDICT_INCOMPLETE:
        /* Says which of the three reasons applies, rather than one vague
         * sentence covering all of them. */
        if (!summary->completed) {
            snprintf(buf, cap,
                     "Nothing found so far, but the scan did not finish - "
                     "this device has not been fully checked.");
        } else if (summary->checks_failed > 0) {
            snprintf(buf, cap,
                     "Nothing found, but %zu check(s) failed - "
                     "this device has not been fully checked.",
                     summary->checks_failed);
        } else {
            snprintf(buf, cap,
                     "Nothing found, but %zu check(s) did not run - "
                     "this device has not been fully checked.",
                     summary->checks_skipped);
        }
        break;
    case GUI_VERDICT_CLEAN:
    default:
        /* Phase 17 (ARCHITECTURE.md section 23.4): skipped locations do not
         * demote the verdict to INCOMPLETE. An unelevated scan of any system
         * volume always meets some (System Volume Information, other users'
         * profiles), so that rule would make ALL CLEAR impossible on every
         * internal drive, and a banner that can never go green says nothing.
         * The claim is narrowed in words instead, here in the one sentence
         * that sits directly under the green headline. */
        if (summary->paths_skipped > 0) {
            snprintf(buf, cap,
                     "No threats in everything that could be read. "
                     "%llu protected location(s) were skipped.",
                     (unsigned long long)summary->paths_skipped);
        } else if (summary->info_count > 0) {
            snprintf(buf, cap,
                     "Every check ran and found no threats. %zu informational note(s) below.",
                     summary->info_count);
        } else {
            snprintf(buf, cap, "Every check ran and found nothing suspicious.");
        }
        break;
    }
    return buf;
}

/* ------------------------------------------------------------------------ *
 * Sections
 * ------------------------------------------------------------------------ */

static void render_verdict(const emit_sink_t *sink, const gui_report_summary_t *summary)
{
    char detail[256];

    emit_fmt(sink, gui_verdict_style(summary->verdict), "   %s\r\n",
             gui_verdict_headline(summary->verdict));
    emit_fmt(sink, GUI_STYLE_MUTED, "   %s\r\n",
             gui_verdict_detail(summary, detail, sizeof(detail)));
}

static void render_device(const emit_sink_t *sink, const usbs_device_t *device)
{
    char identity[USBS_IDENTITY_MAX];
    char line[GUI_LINE_MAX];

    emit_section(sink, "DEVICE");

    /* Drive letter(s) and volume label on one row - together they are how
     * a person actually recognises which stick this is. */
    {
        char     drives[USBS_MOUNT_POINTS_MAX * (USBS_MOUNT_POINT_MAX + 2)];
        size_t   used = 0;
        usbs_u32 i;

        drives[0] = '\0';
        for (i = 0; i < device->mount_point_count && i < USBS_MOUNT_POINTS_MAX; ++i) {
            int written = snprintf(drives + used, sizeof(drives) - used, "%s%s",
                                   (i > 0) ? ", " : "", device->mount_points[i]);
            if (written <= 0 || (size_t)written >= sizeof(drives) - used) {
                break; /* out of room; show what fits rather than overrun */
            }
            used += (size_t)written;
        }
        if (drives[0] == '\0') {
            snprintf(drives, sizeof(drives), "(no drive letter)");
        }
        if (device->label[0] != '\0') {
            snprintf(line, sizeof(line), "%s   %s", drives, device->label);
        } else {
            snprintf(line, sizeof(line), "%s", drives);
        }
        emit_field(sink, "Drive", GUI_STYLE_BODY, line);
    }

    if (device->vendor[0] != '\0' || device->product[0] != '\0') {
        snprintf(line, sizeof(line), "%s%s%s",
                 device->vendor,
                 (device->vendor[0] != '\0' && device->product[0] != '\0') ? " " : "",
                 device->product);
        emit_field(sink, "Hardware", GUI_STYLE_BODY, line);
    }

    if (!usbs_ok(usbs_device_identity(device, identity, sizeof(identity)))) {
        snprintf(identity, sizeof(identity), "(unknown)");
    }
    emit_field(sink, "Device ID", GUI_STYLE_MUTED, identity);

    emit_field(sink, "Connection", GUI_STYLE_BODY, usbs_bus_type_string(device->bus_type));

    if (device->filesystem[0] != '\0') {
        emit_field(sink, "File system", GUI_STYLE_BODY, device->filesystem);
    }

    if (device->capacity_bytes > 0) {
        char capacity[32];
        char used[32];
        format_size(device->capacity_bytes, capacity, sizeof(capacity));
        format_size(device->capacity_bytes - ((device->free_bytes <= device->capacity_bytes)
                                                  ? device->free_bytes
                                                  : device->capacity_bytes),
                    used, sizeof(used));
        snprintf(line, sizeof(line), "%s total  " GUI_MIDDOT "  %s in use", capacity, used);
        emit_field(sink, "Capacity", GUI_STYLE_BODY, line);
    }
}

/* The engine records the final file/byte counts inside file_traversal's own
 * message; nothing on usbs_scan_result_t carries them separately. Rather
 * than parse that string back apart, the message is shown verbatim - it is
 * the engine's own words for what it did. */
static const char *traversal_message(const usbs_scan_result_t *result)
{
    size_t i;
    for (i = 0; i < result->checks.count; ++i) {
        if (strcmp(result->checks.items[i].id, "file_traversal") == 0) {
            return result->checks.items[i].message;
        }
    }
    return NULL;
}

static void render_scan(const emit_sink_t *sink, const usbs_scan_result_t *result,
                        const gui_report_totals_t *totals,
                        const gui_report_summary_t *summary)
{
    const char *traversal;

    emit_section(sink, "SCAN");

    emit_field(sink, "Started", GUI_STYLE_BODY, result->started_at);
    emit_field(sink, "Finished", GUI_STYLE_BODY, result->finished_at);
    /* "Completed" is deliberately NOT styled GUI_STYLE_GOOD. Green is
     * reserved throughout this view for exactly one claim - "nothing bad
     * was found" - so that a glance at any green text carries a single,
     * unambiguous meaning. A scan that mechanically finished while finding
     * a known-malicious file is not good news, and a green word sitting on
     * a red-bannered report is precisely the kind of mixed signal that
     * gets misread. Amber for "stopped early" stays: that warns about the
     * scan's own coverage, which is not a safety claim either way. */
    emit_field(sink, "Outcome",
               summary->completed ? GUI_STYLE_BODY : GUI_STYLE_WARNING,
               summary->completed ? "Completed" : "Stopped early (cancelled, or the device was removed)");

    if (totals != NULL) {
        char line[GUI_LINE_MAX];
        char bytes[32];
        format_size(totals->bytes, bytes, sizeof(bytes));
        snprintf(line, sizeof(line), "%llu file(s)  " GUI_MIDDOT "  %s examined",
                 (unsigned long long)totals->files, bytes);
        emit_field(sink, "Scanned", GUI_STYLE_BODY, line);
        /* The totals line is built from progress counts, not from
         * file_traversal's message, so the skip count that message carries
         * has to be stated separately here (the else branch below shows the
         * message verbatim, and gets it for free). */
        if (result->paths_skipped > 0) {
            snprintf(line, sizeof(line),
                     "%llu location(s) could not be read (access denied or unavailable)",
                     (unsigned long long)result->paths_skipped);
            emit_field(sink, "Skipped", GUI_STYLE_MUTED, line);
        }
        /* Phase 17.1: same reason, for the location policy's exclusions. */
        if (result->paths_excluded > 0) {
            snprintf(line, sizeof(line),
                     "%llu location(s) not examined by internal-drive policy (USB Sentinel test fixtures)",
                     (unsigned long long)result->paths_excluded);
            emit_field(sink, "Excluded", GUI_STYLE_MUTED, line);
        }
    } else {
        traversal = traversal_message(result);
        if (traversal != NULL && traversal[0] != '\0') {
            emit_field(sink, "Scanned", GUI_STYLE_BODY, traversal);
        }
    }

    emit_field(sink, "Scan ID", GUI_STYLE_MUTED, result->scan_id);

    /* Capability gaps are never left to be inferred from the absence of a
     * finding (ARCHITECTURE.md section 7.3) - but they are only worth the
     * reader's attention when something is actually unavailable. */
    if (!result->capabilities.can_read_raw_volume || !result->capabilities.can_read_physical_disk) {
        emit_field(sink, "Limited by", GUI_STYLE_MUTED,
                   "raw volume/disk access unavailable without elevation");
    }
}

/* Findings at or above `floor`, grouped under one heading. Returns how many
 * were emitted so the caller can skip the heading entirely when there are
 * none. */
static size_t render_findings(const emit_sink_t *sink, const usbs_scan_result_t *result,
                              usbs_severity_t floor, usbs_bool exact)
{
    size_t emitted = 0;
    size_t i;

    for (i = 0; i < result->checks.count; ++i) {
        const usbs_check_result_t *check = &result->checks.items[i];
        size_t                     j;

        for (j = 0; j < check->findings.count; ++j) {
            const usbs_finding_t *finding = &check->findings.items[j];

            if (exact ? (finding->severity != floor) : (finding->severity < floor)) {
                continue;
            }

            if (emitted > 0) {
                emit_blank(sink);
            }
            emit_fmt(sink, style_for_severity(finding->severity),
                     "   " GUI_MARKER "  [%s]  %s\r\n",
                     label_for_severity(finding->severity), finding->message);
            if (finding->path[0] != '\0') {
                emit_fmt(sink, GUI_STYLE_MUTED, "        Location:  %s\r\n", finding->path);
            }
            emit_fmt(sink, GUI_STYLE_MUTED, "        Found by:  %s\r\n",
                     gui_check_display_name(check->id));
            ++emitted;
        }
    }
    return emitted;
}

static void render_checks(const emit_sink_t *sink, const usbs_scan_result_t *result,
                          const gui_report_summary_t *summary)
{
    size_t i;

    emit_section(sink, "CHECKS PERFORMED");

    for (i = 0; i < result->checks.count; ++i) {
        const usbs_check_result_t *check = &result->checks.items[i];
        char                       outcome[GUI_LINE_MAX];
        gui_text_style_t           style = GUI_STYLE_BODY;

        switch (check->status) {
        case USBS_CHECK_SKIPPED:
            snprintf(outcome, sizeof(outcome), "skipped " GUI_MIDDOT " %s", check->skip_reason);
            style = GUI_STYLE_WARNING;
            break;
        case USBS_CHECK_FAILED:
            snprintf(outcome, sizeof(outcome), "failed " GUI_MIDDOT " %s", check->message);
            style = GUI_STYLE_WARNING;
            break;
        case USBS_CHECK_RAN:
        default:
            if (check->findings.count == 0) {
                snprintf(outcome, sizeof(outcome), "ran " GUI_MIDDOT " nothing found");
                style = GUI_STYLE_MUTED;
            } else {
                snprintf(outcome, sizeof(outcome), "ran " GUI_MIDDOT " %zu finding(s)",
                         check->findings.count);
                style = GUI_STYLE_BODY;
            }
            break;
        }

        emit_fmt(sink, GUI_STYLE_LABEL, "   " GUI_BULLET "  %-28s ",
                 gui_check_display_name(check->id));
        emit_fmt(sink, style, "%s\r\n", outcome);

        /* A check's own message (hash_match_example's provenance
         * disclaimer, file_traversal's counts) is never dropped for lack of
         * a finding to attach it to - the same rule the CSV column
         * check_message exists for (ARCHITECTURE.md section 13). */
        if (check->status == USBS_CHECK_RAN && check->message[0] != '\0') {
            emit_fmt(sink, GUI_STYLE_MUTED, "        %s\r\n", check->message);
        }
    }

    if (summary->checks_skipped > 0 || summary->checks_failed > 0) {
        emit_blank(sink);
        emit_fmt(sink, GUI_STYLE_WARNING,
                 "   %zu check(s) skipped and %zu failed - this scan is not a clean bill of health.\r\n",
                 summary->checks_skipped, summary->checks_failed);
    }
}

/* ------------------------------------------------------------------------ *
 * Entry point
 * ------------------------------------------------------------------------ */

void gui_report_render_runs(const usbs_scan_result_t  *result,
                            const gui_report_totals_t *totals,
                            gui_text_emit_fn           emit,
                            void                      *ctx)
{
    emit_sink_t          sink;
    gui_report_summary_t summary;

    if (result == NULL || emit == NULL) {
        return;
    }
    sink.fn  = emit;
    sink.ctx = ctx;

    gui_report_summarize(result, &summary);

    emit_text(&sink, GUI_STYLE_TITLE, "USB SENTINEL SCAN REPORT\r\n");
    emit_blank(&sink);

    render_verdict(&sink, &summary);
    emit_blank(&sink);

    render_device(&sink, &result->device);
    emit_blank(&sink);

    render_scan(&sink, result, totals, &summary);
    emit_blank(&sink);

    if (summary.high_count > 0 || summary.warning_count > 0) {
        emit_section(&sink, (summary.high_count > 0) ? "THREATS FOUND" : "SUSPICIOUS ITEMS");
        render_findings(&sink, result, USBS_SEVERITY_WARNING, false);
        emit_blank(&sink);
    }

    if (summary.info_count > 0) {
        emit_section(&sink, "NOTES");
        render_findings(&sink, result, USBS_SEVERITY_INFO, true);
        emit_blank(&sink);
    }

    render_checks(&sink, result, &summary);
    emit_blank(&sink);

    emit_text(&sink, GUI_STYLE_MUTED,
              "   Scanning is read-only: no file on this device was opened for writing.\r\n");
}
