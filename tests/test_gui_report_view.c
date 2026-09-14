/*
 * Headless test of src/gui/gui_report_view.c - Phase 11's testable GUI
 * core. No window, no RichEdit, no hardware: the module emits (style, text)
 * runs through a callback, so a test can collect them into a buffer and
 * assert on both what was said and how loudly, exactly as
 * tests/test_gui_worker.c exercises the scan worker without a window
 * (ARCHITECTURE.md section 17).
 *
 * The verdict rules get the most attention here on purpose. A colour is
 * read at a glance and believed, so "when may this show green?" is a
 * correctness question, not a cosmetic one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gui_report_view.h"
#include "test_util.h"

/* ------------------------------------------------------------------------ *
 * Capture sink
 * ------------------------------------------------------------------------ */

#define CAP_MAX 32768

typedef struct capture {
    char   all[CAP_MAX];
    size_t all_len;
    char   threat[CAP_MAX];
    size_t threat_len;
    char   good[CAP_MAX];
    size_t good_len;
    int    runs;
    int    bad_style;
} capture_t;

static void cap_append(char *buf, size_t *len, const char *text)
{
    size_t n = strlen(text);
    if (*len + n + 1 >= CAP_MAX) {
        return;
    }
    memcpy(buf + *len, text, n + 1);
    *len += n;
}

static void cap_emit(void *ctx, gui_text_style_t style, const char *text)
{
    capture_t *cap = (capture_t *)ctx;

    ++cap->runs;
    if ((int)style < 0 || style >= GUI_STYLE_COUNT) {
        cap->bad_style = 1;
        return;
    }
    cap_append(cap->all, &cap->all_len, text);
    if (style == GUI_STYLE_THREAT) {
        cap_append(cap->threat, &cap->threat_len, text);
    } else if (style == GUI_STYLE_GOOD) {
        cap_append(cap->good, &cap->good_len, text);
    }
}

static void render(const usbs_scan_result_t *result, capture_t *cap)
{
    memset(cap, 0, sizeof(*cap));
    gui_report_render_runs(result, NULL, cap_emit, cap);
}

static usbs_bool contains(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

/* ------------------------------------------------------------------------ *
 * Scan-result builders
 * ------------------------------------------------------------------------ */

static void begin_result(usbs_scan_result_t *result, usbs_scan_status_t status)
{
    usbs_scan_result_init(result);
    snprintf(result->scan_id, sizeof(result->scan_id), "{test-scan-id}");
    snprintf(result->started_at, sizeof(result->started_at), "2026-09-12T10:00:00Z");
    snprintf(result->finished_at, sizeof(result->finished_at), "2026-09-12T10:00:07Z");
    result->status = status;

    result->device.bus_type       = USBS_BUS_USB;
    result->device.media_present  = true;
    result->device.capacity_bytes = 16u * 1024u * 1024u * 1024u;
    result->device.free_bytes     = 4u * 1024u * 1024u * 1024u;
    snprintf(result->device.volume_path, sizeof(result->device.volume_path),
             "\\\\?\\Volume{00000000-0000-0000-0000-000000000001}\\");
    snprintf(result->device.mount_points[0], sizeof(result->device.mount_points[0]), "E:");
    result->device.mount_point_count = 1;
    snprintf(result->device.label, sizeof(result->device.label), "FIELD KIT");
    snprintf(result->device.filesystem, sizeof(result->device.filesystem), "FAT32");

    result->capabilities.can_read_raw_volume    = true;
    result->capabilities.can_read_physical_disk = true;
}

/* Adds a check that ran, with `count` findings all of `severity`. */
static void add_ran_check(usbs_scan_result_t *result, const char *id,
                          usbs_severity_t severity, size_t count, const char *message)
{
    usbs_check_result_t check;
    size_t              i;

    usbs_check_result_init(&check, id);
    for (i = 0; i < count; ++i) {
        usbs_finding_t finding;
        memset(&finding, 0, sizeof(finding));
        finding.severity = severity;
        snprintf(finding.message, sizeof(finding.message), "%s", message);
        snprintf(finding.path, sizeof(finding.path), "\\payload%zu.exe", i);
        USBS_CHECK(usbs_ok(usbs_finding_list_push(&check.findings, &finding)));
    }
    usbs_check_list_push(&result->checks, &check);
}

static void add_traversal(usbs_scan_result_t *result, const char *message)
{
    usbs_check_result_t check;
    usbs_check_result_init(&check, "file_traversal");
    snprintf(check.message, sizeof(check.message), "%s", message);
    usbs_check_list_push(&result->checks, &check);
}

static void add_skipped_check(usbs_scan_result_t *result, const char *id, const char *reason)
{
    usbs_check_result_t check;
    usbs_check_result_init(&check, id);
    usbs_check_result_set_skipped(&check, reason);
    usbs_check_list_push(&result->checks, &check);
}

static void add_failed_check(usbs_scan_result_t *result, const char *id, const char *message)
{
    usbs_check_result_t check;
    usbs_check_result_init(&check, id);
    usbs_check_result_set_failed(&check, message);
    usbs_check_list_push(&result->checks, &check);
}

static gui_verdict_t verdict_of(const usbs_scan_result_t *result)
{
    gui_report_summary_t summary;
    gui_report_summarize(result, &summary);
    return summary.verdict;
}

/* ------------------------------------------------------------------------ *
 * Verdict rules
 * ------------------------------------------------------------------------ */

static void test_clean_is_hard_to_earn(void)
{
    usbs_scan_result_t result;

    /* Completed, every check ran, nothing found: the only way to green. */
    begin_result(&result, USBS_SCAN_COMPLETED);
    add_traversal(&result, "completed: 631 file(s), 12884901888 byte(s)");
    add_ran_check(&result, "autorun_inspection", USBS_SEVERITY_INFO, 0, "");
    USBS_CHECK(verdict_of(&result) == GUI_VERDICT_CLEAN);
    usbs_scan_result_free(&result);

    /* A skipped check means the device was not fully examined. Green here
     * would be a lie told in a colour nobody double-checks. */
    begin_result(&result, USBS_SCAN_COMPLETED);
    add_traversal(&result, "completed: 631 file(s), 0 byte(s)");
    add_skipped_check(&result, "hash_match_example", "no signature file loaded");
    USBS_CHECK(verdict_of(&result) == GUI_VERDICT_INCOMPLETE);
    usbs_scan_result_free(&result);

    /* Same for a check that errored out. */
    begin_result(&result, USBS_SCAN_COMPLETED);
    add_traversal(&result, "completed: 3 file(s), 10 byte(s)");
    add_failed_check(&result, "lnk_inspection", "volume could not be read");
    USBS_CHECK(verdict_of(&result) == GUI_VERDICT_INCOMPLETE);
    usbs_scan_result_free(&result);

    /* And for a scan that never finished, even with a spotless result set. */
    begin_result(&result, USBS_SCAN_ABORTED);
    add_traversal(&result, "cancelled: 12 file(s), 900 byte(s)");
    USBS_CHECK(verdict_of(&result) == GUI_VERDICT_INCOMPLETE);
    usbs_scan_result_free(&result);
}

static void test_severity_outranks_completeness(void)
{
    usbs_scan_result_t result;

    begin_result(&result, USBS_SCAN_COMPLETED);
    add_traversal(&result, "completed: 631 file(s), 5 byte(s)");
    add_ran_check(&result, "hash_match_example", USBS_SEVERITY_HIGH, 1, "matches a known-malicious hash");
    USBS_CHECK(verdict_of(&result) == GUI_VERDICT_THREAT);
    usbs_scan_result_free(&result);

    /* A high-severity hit found before the scan was cut short is still the
     * most important thing on screen - it must not be demoted to
     * "incomplete". */
    begin_result(&result, USBS_SCAN_ABORTED);
    add_traversal(&result, "cancelled: 40 file(s), 5 byte(s)");
    add_ran_check(&result, "suspicious_filename", USBS_SEVERITY_HIGH, 2, "double extension");
    add_skipped_check(&result, "autorun_inspection", "scan cancelled before this check ran");
    USBS_CHECK(verdict_of(&result) == GUI_VERDICT_THREAT);
    usbs_scan_result_free(&result);

    /* Warnings alone are suspicious, not a threat. */
    begin_result(&result, USBS_SCAN_COMPLETED);
    add_traversal(&result, "completed: 631 file(s), 5 byte(s)");
    add_ran_check(&result, "lnk_inspection", USBS_SEVERITY_WARNING, 1, "shortcut targets cmd.exe");
    USBS_CHECK(verdict_of(&result) == GUI_VERDICT_SUSPICIOUS);
    usbs_scan_result_free(&result);

    /* Informational notes do not demote a clean scan. */
    begin_result(&result, USBS_SCAN_COMPLETED);
    add_traversal(&result, "completed: 631 file(s), 5 byte(s)");
    add_ran_check(&result, "autorun_inspection", USBS_SEVERITY_INFO, 1, "autorun.inf present, no launch directive");
    USBS_CHECK(verdict_of(&result) == GUI_VERDICT_CLEAN);
    usbs_scan_result_free(&result);
}

static void test_summary_counts(void)
{
    usbs_scan_result_t   result;
    gui_report_summary_t summary;

    begin_result(&result, USBS_SCAN_COMPLETED);
    add_traversal(&result, "completed: 631 file(s), 5 byte(s)");
    add_ran_check(&result, "hash_match_example", USBS_SEVERITY_HIGH, 2, "known-malicious hash");
    add_ran_check(&result, "lnk_inspection", USBS_SEVERITY_WARNING, 3, "shortcut targets cmd.exe");
    add_ran_check(&result, "autorun_inspection", USBS_SEVERITY_INFO, 1, "autorun.inf present");
    add_skipped_check(&result, "suspicious_filename", "not run");

    gui_report_summarize(&result, &summary);
    USBS_CHECK(summary.high_count == 2);
    USBS_CHECK(summary.warning_count == 3);
    USBS_CHECK(summary.info_count == 1);
    USBS_CHECK(summary.finding_count == 6);
    USBS_CHECK(summary.checks_run == 4); /* traversal + three detectors */
    USBS_CHECK(summary.checks_skipped == 1);
    USBS_CHECK(summary.checks_failed == 0);
    USBS_CHECK(summary.completed);
    usbs_scan_result_free(&result);
}

static void test_null_result_is_not_clean(void)
{
    gui_report_summary_t summary;
    capture_t            cap;

    gui_report_summarize(NULL, &summary);
    USBS_CHECK(summary.verdict == GUI_VERDICT_INCOMPLETE);
    USBS_CHECK(summary.finding_count == 0);

    /* NULL-safe, and emits nothing rather than a half-built report. */
    render(NULL, &cap);
    USBS_CHECK(cap.runs == 0);

    /* Also NULL-safe on the out-parameter and on the emit callback. */
    gui_report_summarize(NULL, NULL);
}

/* ------------------------------------------------------------------------ *
 * Rendering
 * ------------------------------------------------------------------------ */

static void test_threat_text_is_styled_as_a_threat(void)
{
    usbs_scan_result_t result;
    capture_t          cap;

    begin_result(&result, USBS_SCAN_COMPLETED);
    add_traversal(&result, "completed: 631 file(s), 5 byte(s)");
    add_ran_check(&result, "hash_match_example", USBS_SEVERITY_HIGH, 1,
                  "matches a known-malicious hash");

    render(&result, &cap);

    USBS_CHECK(!cap.bad_style);
    USBS_CHECK(cap.runs > 0);

    /* The headline and the finding itself both carry the threat style -
     * this is the assertion that would fail if the finding were rendered
     * in body text and only the banner were coloured. */
    USBS_CHECK(contains(cap.threat, "THREATS DETECTED"));
    USBS_CHECK(contains(cap.threat, "matches a known-malicious hash"));
    USBS_CHECK(contains(cap.threat, "HIGH"));

    /* Supporting detail is present, and the section exists. */
    USBS_CHECK(contains(cap.all, "THREATS FOUND"));
    USBS_CHECK(contains(cap.all, "payload0.exe"));
    USBS_CHECK(contains(cap.all, "Known-hash matching")); /* friendly check name */

    /* Nothing green anywhere in a report with a high-severity finding.
     * Green is reserved for the single claim "nothing bad was found", so a
     * threat report must contain none of it - not even on the scan's own
     * "Completed" outcome line, which is about coverage rather than
     * safety. */
    USBS_CHECK(cap.good_len == 0);

    usbs_scan_result_free(&result);
}

static void test_clean_report_reads_clean(void)
{
    usbs_scan_result_t result;
    capture_t          cap;

    begin_result(&result, USBS_SCAN_COMPLETED);
    add_traversal(&result, "completed: 631 file(s), 12884901888 byte(s)");
    add_ran_check(&result, "autorun_inspection", USBS_SEVERITY_INFO, 0, "");

    render(&result, &cap);

    USBS_CHECK(!cap.bad_style);
    USBS_CHECK(contains(cap.good, "ALL CLEAR"));
    USBS_CHECK(cap.threat_len == 0);

    /* The verdict headline is the ONLY thing allowed to be green, even in
     * a report where everything went well - so that green never has to be
     * read in context to be understood. */
    USBS_CHECK(!contains(cap.good, "Completed"));
    USBS_CHECK(!contains(cap.good, "DEVICE"));
    USBS_CHECK(!contains(cap.good, "FAT32"));
    USBS_CHECK(!contains(cap.all, "THREATS FOUND"));
    USBS_CHECK(!contains(cap.all, "SUSPICIOUS ITEMS"));

    /* Device and scan facts a non-technical reader needs to confirm they
     * are looking at the right stick. */
    USBS_CHECK(contains(cap.all, "DEVICE"));
    USBS_CHECK(contains(cap.all, "FIELD KIT"));
    USBS_CHECK(contains(cap.all, "E:"));
    USBS_CHECK(contains(cap.all, "FAT32"));
    USBS_CHECK(contains(cap.all, "CHECKS PERFORMED"));
    USBS_CHECK(contains(cap.all, "read-only"));

    usbs_scan_result_free(&result);
}

static void test_incomplete_scan_says_why(void)
{
    usbs_scan_result_t result;
    capture_t          cap;

    begin_result(&result, USBS_SCAN_ABORTED);
    add_traversal(&result, "cancelled: 40 file(s), 900 byte(s)");
    add_skipped_check(&result, "autorun_inspection", "scan cancelled before this check ran");

    render(&result, &cap);

    USBS_CHECK(!cap.bad_style);
    USBS_CHECK(cap.good_len == 0); /* never green */
    USBS_CHECK(contains(cap.all, "SCAN INCOMPLETE"));
    USBS_CHECK(contains(cap.all, "did not finish"));
    /* The skip reason is carried through, never left to be inferred from
     * the absence of a finding. */
    USBS_CHECK(contains(cap.all, "scan cancelled before this check ran"));
    USBS_CHECK(contains(cap.all, "not a clean bill of health"));

    usbs_scan_result_free(&result);
}

static void test_check_messages_survive(void)
{
    usbs_scan_result_t  result;
    capture_t           cap;
    usbs_check_result_t check;

    begin_result(&result, USBS_SCAN_COMPLETED);
    add_traversal(&result, "completed: 631 file(s), 5 byte(s)");

    /* A check that ran, found nothing, but has something important to say
     * - hash_match_example's provenance disclaimer is the real case. */
    usbs_check_result_init(&check, "hash_match_example");
    snprintf(check.message, sizeof(check.message),
             "example detector: verify its provenance yourself.");
    usbs_check_list_push(&result.checks, &check);

    render(&result, &cap);
    USBS_CHECK(contains(cap.all, "verify its provenance yourself."));

    usbs_scan_result_free(&result);
}

static void test_display_names(void)
{
    USBS_CHECK_STR_EQ(gui_check_display_name("autorun_inspection"), "Autorun inspection");
    USBS_CHECK_STR_EQ(gui_check_display_name("file_traversal"), "File traversal");
    USBS_CHECK_STR_EQ(gui_check_display_name("hash_match_example"), "Known-hash matching");
    /* An unknown id degrades to itself rather than disappearing. */
    USBS_CHECK_STR_EQ(gui_check_display_name("some_future_detector"), "some_future_detector");
    USBS_CHECK(gui_check_display_name(NULL) != NULL);
}

static void test_headlines_and_styles(void)
{
    USBS_CHECK_STR_EQ(gui_verdict_headline(GUI_VERDICT_CLEAN), "ALL CLEAR");
    USBS_CHECK_STR_EQ(gui_verdict_headline(GUI_VERDICT_THREAT), "THREATS DETECTED");
    USBS_CHECK(gui_verdict_style(GUI_VERDICT_CLEAN) == GUI_STYLE_GOOD);
    USBS_CHECK(gui_verdict_style(GUI_VERDICT_THREAT) == GUI_STYLE_THREAT);
    /* Incomplete must never be styled as good. */
    USBS_CHECK(gui_verdict_style(GUI_VERDICT_INCOMPLETE) != GUI_STYLE_GOOD);
    USBS_CHECK(gui_verdict_style(GUI_VERDICT_SUSPICIOUS) != GUI_STYLE_GOOD);

    {
        char buf[256];
        USBS_CHECK(gui_verdict_detail(NULL, buf, sizeof(buf)) == buf);
        USBS_CHECK(buf[0] != '\0');
    }
}

static void test_totals_override_traversal_message(void)
{
    usbs_scan_result_t  result;
    capture_t           cap;
    gui_report_totals_t totals;

    begin_result(&result, USBS_SCAN_COMPLETED);
    add_traversal(&result, "completed: 631 file(s), 12884901888 byte(s)");

    totals.files = 631;
    totals.bytes = 12884901888ull;

    memset(&cap, 0, sizeof(cap));
    gui_report_render_runs(&result, &totals, cap_emit, &cap);

    /* With totals supplied, bytes are shown in human units rather than the
     * engine's raw byte count. */
    USBS_CHECK(contains(cap.all, "631 file(s)"));
    USBS_CHECK(contains(cap.all, "12.0 GiB"));

    usbs_scan_result_free(&result);
}

/*
 * Phase 17 (ARCHITECTURE.md section 23.4): locations a whole-drive scan was
 * refused (System Volume Information and similar) do not demote the
 * verdict. Every unelevated scan of a system volume has some, so treating
 * them as INCOMPLETE would make green unreachable on any internal drive.
 * The green claim is narrowed in words instead. So this test checks both
 * halves: the verdict stays CLEAN, and the reader is told what was not
 * read, in the banner detail, the report body, and with totals present.
 */
static void test_skipped_locations_are_disclosed_not_demoted(void)
{
    static capture_t     cap; /* ~100 KB: kept off the stack */
    usbs_scan_result_t   result;
    gui_report_summary_t summary;
    gui_report_totals_t  totals;
    char                 detail[256];

    begin_result(&result, USBS_SCAN_COMPLETED);
    result.device.bus_type = USBS_BUS_NVME;
    result.paths_skipped   = 14;
    add_traversal(&result, "completed: 412113 file(s), 188000000000 byte(s), "
                           "14 location(s) skipped (access denied or unavailable)");
    add_ran_check(&result, "autorun_inspection", USBS_SEVERITY_INFO, 0, "");

    gui_report_summarize(&result, &summary);
    USBS_CHECK(summary.verdict == GUI_VERDICT_CLEAN);
    USBS_CHECK(summary.paths_skipped == 14);

    gui_verdict_detail(&summary, detail, sizeof(detail));
    USBS_CHECK(contains(detail, "14 protected location(s) were skipped"));
    /* The unqualified sentence must not appear when something was skipped. */
    USBS_CHECK(!contains(detail, "Every check ran and found nothing suspicious"));

    /* Without totals, the traversal message (which carries the count) is
     * shown verbatim. */
    render(&result, &cap);
    USBS_CHECK(contains(cap.all, "14 location(s) skipped"));

    /* With totals, the Scanned line is rebuilt from counts and no longer
     * carries the message, so the skip count must be stated on its own. */
    memset(&cap, 0, sizeof(cap));
    totals.files = 412113;
    totals.bytes = 188000000000ull;
    gui_report_render_runs(&result, &totals, cap_emit, &cap);
    USBS_CHECK(contains(cap.all, "14 location(s) could not be read"));
    USBS_CHECK(!contains(cap.all, "not examined")); /* nothing excluded yet */

    /* Phase 17.1: the location policy's exclusions get the same treatment. */
    result.paths_excluded = 3;
    memset(&cap, 0, sizeof(cap));
    gui_report_render_runs(&result, &totals, cap_emit, &cap);
    USBS_CHECK(contains(cap.all, "3 location(s) not examined by internal-drive policy"));
    usbs_scan_result_free(&result);

    /* Nothing skipped: the pre-Phase-17 wording, unchanged. */
    begin_result(&result, USBS_SCAN_COMPLETED);
    add_traversal(&result, "completed: 631 file(s), 5 byte(s)");
    add_ran_check(&result, "autorun_inspection", USBS_SEVERITY_INFO, 0, "");
    gui_report_summarize(&result, &summary);
    gui_verdict_detail(&summary, detail, sizeof(detail));
    USBS_CHECK_STR_EQ(detail, "Every check ran and found nothing suspicious.");
    memset(&cap, 0, sizeof(cap));
    gui_report_render_runs(&result, &totals, cap_emit, &cap);
    USBS_CHECK(!contains(cap.all, "could not be read"));
    usbs_scan_result_free(&result);
}

int main(void)
{
    test_clean_is_hard_to_earn();
    test_severity_outranks_completeness();
    test_summary_counts();
    test_null_result_is_not_clean();
    test_threat_text_is_styled_as_a_threat();
    test_clean_report_reads_clean();
    test_incomplete_scan_says_why();
    test_check_messages_survive();
    test_display_names();
    test_headlines_and_styles();
    test_totals_override_traversal_message();
    test_skipped_locations_are_disclosed_not_demoted();
    return USBS_TEST_RESULT();
}
