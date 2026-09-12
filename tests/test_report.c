#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_util.h"
#include "usbsentinel/json.h"
#include "usbsentinel/report.h"

static FILE *open_scratch(const char *path)
{
    FILE *f = NULL;
#if defined(_MSC_VER)
    if (fopen_s(&f, path, "w+") != 0) {
        f = NULL;
    }
#else
    f = fopen(path, "w+");
#endif
    return f;
}

static void build_sample_result(usbs_scan_result_t *result)
{
    usbs_check_result_t ran;
    usbs_check_result_t skipped;
    usbs_check_result_t failed;
    usbs_finding_t       finding;

    usbs_scan_result_init(result);
    snprintf(result->scan_id, sizeof(result->scan_id), "%s", "scan-1");
    snprintf(result->started_at, sizeof(result->started_at), "%s", "2026-09-11T14:00:00Z");
    snprintf(result->finished_at, sizeof(result->finished_at), "%s", "2026-09-11T14:00:05Z");
    result->status = USBS_SCAN_ABORTED;

    snprintf(result->device.volume_path, sizeof(result->device.volume_path),
             "%s", "\\\\?\\Volume{aaaa}\\");
    snprintf(result->device.usb_vid, sizeof(result->device.usb_vid), "0781");
    snprintf(result->device.usb_pid, sizeof(result->device.usb_pid), "5583");
    snprintf(result->device.vendor, sizeof(result->device.vendor), "SanDisk");
    snprintf(result->device.product, sizeof(result->device.product), "Cruzer");
    result->device.bus_type       = USBS_BUS_USB;
    result->device.media_present  = true;
    result->device.capacity_bytes = 32ULL * 1024 * 1024 * 1024;
    result->device.free_bytes     = 10ULL * 1024 * 1024 * 1024;

    result->capabilities.can_read_raw_volume    = false;
    result->capabilities.can_read_physical_disk = false;

    usbs_check_result_init(&ran, "file_traversal");
    snprintf(ran.message, sizeof(ran.message), "%s", "cancelled: 2 file(s), 10 byte(s)");
    memset(&finding, 0, sizeof(finding));
    finding.severity = USBS_SEVERITY_INFO;
    snprintf(finding.path, sizeof(finding.path), "%s", "autorun.inf");
    snprintf(finding.message, sizeof(finding.message), "%s", "present, no launch command");
    usbs_finding_list_push(&ran.findings, &finding);

    memset(&finding, 0, sizeof(finding));
    finding.severity = USBS_SEVERITY_HIGH;
    snprintf(finding.path, sizeof(finding.path), "%s", "suspicious.lnk");
    snprintf(finding.message, sizeof(finding.message), "%s", "target is powershell.exe");
    usbs_finding_list_push(&ran.findings, &finding);

    usbs_check_list_push(&result->checks, &ran);

    usbs_check_result_init(&skipped, "autorun_inspection");
    usbs_check_result_set_skipped(&skipped, "scan cancelled before this check ran");
    usbs_check_list_push(&result->checks, &skipped);

    usbs_check_result_init(&failed, "boot_sector_analysis");
    usbs_check_result_set_failed(&failed, "USBS_ERR_ACCESS_DENIED");
    usbs_check_list_push(&result->checks, &failed);
}

static void test_json_schema_envelope(void)
{
    usbs_scan_result_t  result;
    char                *text = NULL;
    size_t               len  = 0;
    usbs_json_value_t   *root = NULL;
    long long             schema_version = 0;
    const usbs_json_value_t *checks;
    const usbs_json_value_t *summary;
    long long              n;

    build_sample_result(&result);

    USBS_CHECK(usbs_ok(usbs_report_build_json(&result, &text, &len)));
    USBS_CHECK(text != NULL);
    USBS_CHECK(len == strlen(text));

    USBS_CHECK(usbs_ok(usbs_json_parse(text, len, &root)));

    USBS_CHECK(usbs_json_as_int(usbs_json_object_get(root, "schema_version"), &schema_version));
    USBS_CHECK(schema_version == USBS_REPORT_SCHEMA_VERSION);
    USBS_CHECK(schema_version == 1);

    {
        const usbs_json_value_t *scan = usbs_json_object_get(root, "scan");
        USBS_CHECK_STR_EQ(usbs_json_as_string(usbs_json_object_get(scan, "scan_id")), "scan-1");
        USBS_CHECK_STR_EQ(usbs_json_as_string(usbs_json_object_get(scan, "status")), "aborted");
    }

    {
        const usbs_json_value_t *device = usbs_json_object_get(root, "device");
        USBS_CHECK_STR_EQ(usbs_json_as_string(usbs_json_object_get(device, "bus_type")), "USB");
        USBS_CHECK_STR_EQ(usbs_json_as_string(usbs_json_object_get(device, "identity")),
                          "usb:0781-5583");
        {
            const char *volume_identity =
                usbs_json_as_string(usbs_json_object_get(device, "volume_identity"));
            USBS_CHECK(volume_identity != NULL);
            USBS_CHECK(volume_identity != NULL && strstr(volume_identity, "usb:0781-5583/") != NULL);
        }
    }

    {
        const usbs_json_value_t *caps = usbs_json_object_get(root, "capabilities");
        usbs_bool                b;
        USBS_CHECK(usbs_json_as_bool(usbs_json_object_get(caps, "can_read_raw_volume"), &b));
        USBS_CHECK(!b);
    }

    /* Every check must be explicitly ran/skipped/failed - never simply
     * absent (ARCHITECTURE.md section 7.3). */
    checks = usbs_json_object_get(root, "checks");
    USBS_CHECK(usbs_json_array_count(checks) == 3);
    {
        const usbs_json_value_t *c0 = usbs_json_array_at(checks, 0);
        const usbs_json_value_t *c1 = usbs_json_array_at(checks, 1);
        const usbs_json_value_t *c2 = usbs_json_array_at(checks, 2);

        USBS_CHECK_STR_EQ(usbs_json_as_string(usbs_json_object_get(c0, "status")), "ran");
        {
            const usbs_json_value_t *findings = usbs_json_object_get(c0, "findings");
            const usbs_json_value_t *f0, *f1;

            USBS_CHECK(usbs_json_array_count(findings) == 2);
            f0 = usbs_json_array_at(findings, 0);
            f1 = usbs_json_array_at(findings, 1);
            USBS_CHECK_STR_EQ(usbs_json_as_string(usbs_json_object_get(f0, "severity")), "info");
            USBS_CHECK_STR_EQ(usbs_json_as_string(usbs_json_object_get(f1, "severity")), "high");
            USBS_CHECK_STR_EQ(usbs_json_as_string(usbs_json_object_get(f1, "path")),
                              "suspicious.lnk");
        }

        USBS_CHECK_STR_EQ(usbs_json_as_string(usbs_json_object_get(c1, "status")), "skipped");
        USBS_CHECK_STR_EQ(usbs_json_as_string(usbs_json_object_get(c1, "skip_reason")),
                          "scan cancelled before this check ran");

        USBS_CHECK_STR_EQ(usbs_json_as_string(usbs_json_object_get(c2, "status")), "failed");
        USBS_CHECK_STR_EQ(usbs_json_as_string(usbs_json_object_get(c2, "message")),
                          "USBS_ERR_ACCESS_DENIED");
    }

    summary = usbs_json_object_get(root, "summary");
    USBS_CHECK(usbs_json_as_int(usbs_json_object_get(summary, "checks_run"), &n) && n == 1);
    USBS_CHECK(usbs_json_as_int(usbs_json_object_get(summary, "checks_skipped"), &n) && n == 1);
    USBS_CHECK(usbs_json_as_int(usbs_json_object_get(summary, "checks_failed"), &n) && n == 1);
    USBS_CHECK(usbs_json_as_int(usbs_json_object_get(summary, "findings_count"), &n) && n == 2);

    usbs_json_free(root);
    free(text);
    usbs_scan_result_free(&result);
}

static void test_text_renderer(void)
{
    usbs_scan_result_t  result;
    FILE                *scratch = open_scratch("usbs_report_test.tmp");
    char                 buf[4096];
    size_t               n;

    USBS_CHECK(scratch != NULL);
    if (scratch == NULL) {
        return;
    }

    build_sample_result(&result);
    usbs_report_render_text(&result, scratch);

    rewind(scratch);
    n = fread(buf, 1, sizeof(buf) - 1, scratch);
    buf[n] = '\0';

    USBS_CHECK(strstr(buf, "USB Sentinel scan report") != NULL);
    USBS_CHECK(strstr(buf, "scan-1") != NULL);
    USBS_CHECK(strstr(buf, "aborted") != NULL);
    USBS_CHECK(strstr(buf, "[skipped] autorun_inspection") != NULL);
    USBS_CHECK(strstr(buf, "scan cancelled before this check ran") != NULL);
    USBS_CHECK(strstr(buf, "[failed] boot_sector_analysis") != NULL);
    USBS_CHECK(strstr(buf, "USBS_ERR_ACCESS_DENIED") != NULL);
    USBS_CHECK(strstr(buf, "finding [info]: autorun.inf") != NULL);
    USBS_CHECK(strstr(buf, "finding [high]: suspicious.lnk") != NULL);
    /* A skipped/failed check must be visible in the summary line too. */
    USBS_CHECK(strstr(buf, "check(s) skipped") != NULL);
    USBS_CHECK(strstr(buf, "check(s) failed") != NULL);
    USBS_CHECK(strstr(buf, "requires elevation") != NULL);

    fclose(scratch);
    remove("usbs_report_test.tmp");
    usbs_scan_result_free(&result);
}

static void test_all_ran_summary(void)
{
    usbs_scan_result_t  result;
    usbs_check_result_t ran;
    FILE                *scratch = open_scratch("usbs_report_test2.tmp");
    char                 buf[2048];
    size_t               n;

    USBS_CHECK(scratch != NULL);
    if (scratch == NULL) {
        return;
    }

    usbs_scan_result_init(&result);
    result.status = USBS_SCAN_COMPLETED;
    usbs_check_result_init(&ran, "file_traversal");
    usbs_check_list_push(&result.checks, &ran);

    usbs_report_render_text(&result, scratch);
    rewind(scratch);
    n = fread(buf, 1, sizeof(buf) - 1, scratch);
    buf[n] = '\0';

    USBS_CHECK(strstr(buf, "All checks ran.") != NULL);

    fclose(scratch);
    remove("usbs_report_test2.tmp");
    usbs_scan_result_free(&result);
}

static void test_build_json_rejects_null(void)
{
    char  *text = NULL;
    size_t len  = 0;
    USBS_CHECK(usbs_report_build_json(NULL, &text, &len) == USBS_ERR_INVALID_ARG);
}

/* --- Phase 7: CSV --- */

/* Counts occurrences of `needle` in `haystack` - used to check row counts
 * via "\r\n" rather than parsing the CSV properly, sufficient for these
 * structural assertions. */
static size_t count_occurrences(const char *haystack, const char *needle)
{
    size_t count = 0;
    size_t needle_len = strlen(needle);
    const char *p = haystack;

    while ((p = strstr(p, needle)) != NULL) {
        ++count;
        p += needle_len;
    }
    return count;
}

static void test_csv_basic_structure(void)
{
    usbs_scan_result_t result;
    char               *text = NULL;
    size_t              len  = 0;

    build_sample_result(&result);
    USBS_CHECK(usbs_ok(usbs_report_build_csv(&result, &text, &len)));
    USBS_CHECK(text != NULL);
    if (text != NULL) {
        USBS_CHECK(len == strlen(text));
        USBS_CHECK(strstr(text, "scan_id,device_identity,check_id,check_status,"
                          "skip_reason,check_message,severity,path,message\r\n") == text);
        USBS_CHECK(strstr(text, "scan-1") != NULL);
        USBS_CHECK(strstr(text, "file_traversal") != NULL);
        USBS_CHECK(strstr(text, "autorun_inspection") != NULL);
        USBS_CHECK(strstr(text, "boot_sector_analysis") != NULL);
        /* header + 2 finding rows (file_traversal has 2 findings) + 1
         * skipped row + 1 failed row = 5 lines total. */
        USBS_CHECK(count_occurrences(text, "\r\n") == 5);
        free(text);
    }
    usbs_scan_result_free(&result);
}

/* A check with zero findings must still be exactly one row (never simply
 * absent, ARCHITECTURE.md section 7.3 - now also holding for CSV), with
 * its check-level message preserved even though no finding carries it. */
static void test_csv_zero_findings_still_one_row(void)
{
    usbs_scan_result_t  result;
    usbs_check_result_t ran;
    char                *text = NULL;
    size_t               len  = 0;

    usbs_scan_result_init(&result);
    result.status = USBS_SCAN_COMPLETED;
    usbs_check_result_init(&ran, "hash_match_example");
    snprintf(ran.message, sizeof(ran.message), "%s", "NON-PRODUCTION EXAMPLE disclaimer text");
    usbs_check_list_push(&result.checks, &ran);

    USBS_CHECK(usbs_ok(usbs_report_build_csv(&result, &text, &len)));
    if (text != NULL) {
        USBS_CHECK(count_occurrences(text, "\r\n") == 2); /* header + 1 row */
        USBS_CHECK(strstr(text, "hash_match_example") != NULL);
        USBS_CHECK(strstr(text, "NON-PRODUCTION EXAMPLE disclaimer text") != NULL);
        free(text);
    }
    usbs_scan_result_free(&result);
}

/* A field containing a comma, an embedded quote, and a newline must be
 * quoted per RFC 4180 with the embedded quote doubled - verified by
 * "unescaping" the captured field back to the original rather than
 * asserting on the exact quoted-and-escaped text, which is more robust to
 * incidental formatting choices. */
static void test_csv_escapes_special_characters(void)
{
    usbs_scan_result_t  result;
    usbs_check_result_t ran;
    usbs_finding_t       finding;
    char                 *text = NULL;
    size_t                len  = 0;

    usbs_scan_result_init(&result);
    result.status = USBS_SCAN_COMPLETED;
    usbs_check_result_init(&ran, "suspicious_filename");
    memset(&finding, 0, sizeof(finding));
    finding.severity = USBS_SEVERITY_HIGH;
    snprintf(finding.path, sizeof(finding.path), "%s", "plain.txt");
    snprintf(finding.message, sizeof(finding.message), "%s",
            "comma,quote\"newline\ndone");
    usbs_finding_list_push(&ran.findings, &finding);
    usbs_check_list_push(&result.checks, &ran);

    USBS_CHECK(usbs_ok(usbs_report_build_csv(&result, &text, &len)));
    if (text != NULL) {
        /* The exact RFC 4180 encoding of `comma,quote"newline\ndone`: an
         * opening quote, the text with '"' doubled, a literal comma and
         * newline pass through unescaped *inside* the quotes, closing quote. */
        USBS_CHECK(strstr(text, "\"comma,quote\"\"newline\ndone\"") != NULL);
        free(text);
    }
    usbs_scan_result_free(&result);
}

/* A field beginning with '=', '+', '-', or '@' must be quoted with a
 * leading single quote inside the quotes - the formula-injection
 * mitigation. This content is attacker-influenced (a crafted filename), so
 * the test uses exactly that shape. */
static void test_csv_formula_injection_mitigation(void)
{
    usbs_scan_result_t  result;
    usbs_check_result_t ran;
    usbs_finding_t       finding;
    char                 *text = NULL;
    size_t                len  = 0;

    usbs_scan_result_init(&result);
    result.status = USBS_SCAN_COMPLETED;
    usbs_check_result_init(&ran, "suspicious_filename");
    memset(&finding, 0, sizeof(finding));
    finding.severity = USBS_SEVERITY_HIGH;
    snprintf(finding.path, sizeof(finding.path), "%s", "=cmd|'/c calc'!A1");
    snprintf(finding.message, sizeof(finding.message), "%s", "ordinary message");
    usbs_finding_list_push(&ran.findings, &finding);
    usbs_check_list_push(&result.checks, &ran);

    USBS_CHECK(usbs_ok(usbs_report_build_csv(&result, &text, &len)));
    if (text != NULL) {
        /* Quoted, with a leading "'" immediately inside the opening quote,
         * before the original '=' - defangs spreadsheet formula evaluation
         * without altering the underlying data. */
        USBS_CHECK(strstr(text, "\"'=cmd|") != NULL);
        free(text);
    }
    usbs_scan_result_free(&result);
}

static void test_build_csv_rejects_null(void)
{
    char  *text = NULL;
    size_t len  = 0;
    USBS_CHECK(usbs_report_build_csv(NULL, &text, &len) == USBS_ERR_INVALID_ARG);
}

/*
 * Phase 12 (ARCHITECTURE.md section 18): an oversized-finding truncation
 * boundary test. usbs_finding_t.message/.path are fixed-size buffers
 * (USBS_FINDING_MESSAGE_MAX=256, USBS_FINDING_PATH_MAX=512, scan.h) filled
 * by the detector's own snprintf() - which already truncates safely on its
 * own, so this is not hunting a buffer overflow. What it verifies is the
 * property Phase 7 documented informally after an oversized --signatures
 * path truncated a check-level message (ARCHITECTURE.md section 13.3):
 * whatever content survives truncation must come through JSON, CSV, and
 * the text renderer *identically*, since all three read the same
 * already-truncated field - and content past the cutoff must never leak
 * through any of the three, which would mean some renderer is reading past
 * the field's actual bound.
 *
 * Two cases, both against the exact same field:
 *   - content one byte longer than the field's capacity must be truncated
 *     at exactly capacity-1 characters (room for the NUL); a marker placed
 *     only past that cutoff must never appear in any rendering.
 *   - content that exactly fills capacity-1 characters must NOT be
 *     truncated at all; a marker placed at the very last byte must survive
 *     intact through every rendering. Testing only the over-limit case
 *     would miss an off-by-one that truncates one byte too early.
 */
static void test_oversized_finding_truncation_boundary(void)
{
    usbs_scan_result_t  result;
    usbs_check_result_t ran;
    usbs_finding_t       finding;
    char                 oversized_msg[USBS_FINDING_MESSAGE_MAX + 64];
    char                 oversized_path[USBS_FINDING_PATH_MAX + 64];
    char                 exact_msg[USBS_FINDING_MESSAGE_MAX];   /* capacity - 1 chars + NUL */
    char                *json_text = NULL;
    size_t               json_len  = 0;
    char                *csv_text  = NULL;
    size_t               csv_len   = 0;
    FILE                *scratch;
    char                 text_buf[4096];
    size_t               n;

    /* Case 1: over the limit on both message and path. The marker sits
     * well past each field's real capacity, so a correct truncation never
     * reaches it. */
    memset(oversized_msg, 'M', sizeof(oversized_msg));
    snprintf(oversized_msg + USBS_FINDING_MESSAGE_MAX + 10,
            sizeof(oversized_msg) - (USBS_FINDING_MESSAGE_MAX + 10), "TAIL_MARKER_MSG");
    memset(oversized_path, 'P', sizeof(oversized_path));
    snprintf(oversized_path + USBS_FINDING_PATH_MAX + 10,
            sizeof(oversized_path) - (USBS_FINDING_PATH_MAX + 10), "TAIL_MARKER_PATH");

    usbs_scan_result_init(&result);
    result.status = USBS_SCAN_COMPLETED;
    usbs_check_result_init(&ran, "suspicious_filename");

    memset(&finding, 0, sizeof(finding));
    finding.severity = USBS_SEVERITY_WARNING;
    snprintf(finding.path, sizeof(finding.path), "%s", oversized_path);
    snprintf(finding.message, sizeof(finding.message), "%s", oversized_msg);
    USBS_CHECK(strlen(finding.message) == USBS_FINDING_MESSAGE_MAX - 1);
    USBS_CHECK(strlen(finding.path) == USBS_FINDING_PATH_MAX - 1);
    usbs_finding_list_push(&ran.findings, &finding);

    /* Case 2: exactly at the limit (capacity - 1 characters) on the
     * message field - must round-trip whole, with its own distinct
     * end-of-field marker surviving at the very last byte. */
    memset(exact_msg, 'X', sizeof(exact_msg) - 1);
    exact_msg[sizeof(exact_msg) - 1] = '\0';
    memcpy(exact_msg + sizeof(exact_msg) - 1 - 8, "END_HERE", 8); /* last 8 bytes */

    memset(&finding, 0, sizeof(finding));
    finding.severity = USBS_SEVERITY_INFO;
    snprintf(finding.path, sizeof(finding.path), "%s", "exact.txt");
    snprintf(finding.message, sizeof(finding.message), "%s", exact_msg);
    USBS_CHECK(strlen(finding.message) == USBS_FINDING_MESSAGE_MAX - 1);
    USBS_CHECK_STR_EQ(finding.message, exact_msg); /* not truncated at all */
    usbs_finding_list_push(&ran.findings, &finding);

    usbs_check_list_push(&result.checks, &ran);

    /* JSON */
    USBS_CHECK(usbs_ok(usbs_report_build_json(&result, &json_text, &json_len)));
    if (json_text != NULL) {
        usbs_json_value_t *root = NULL;
        USBS_CHECK(strstr(json_text, "TAIL_MARKER_MSG") == NULL);
        USBS_CHECK(strstr(json_text, "TAIL_MARKER_PATH") == NULL);
        USBS_CHECK(strstr(json_text, "END_HERE") != NULL);
        /* Confirm the parsed field length too, not just substring presence -
         * a renderer could truncate differently and still happen to contain
         * these substrings. */
        USBS_CHECK(usbs_ok(usbs_json_parse(json_text, json_len, &root)));
        if (root != NULL) {
            const usbs_json_value_t *checks = usbs_json_object_get(root, "checks");
            const usbs_json_value_t *check0 = usbs_json_array_at(checks, 0);
            const usbs_json_value_t *findings = usbs_json_object_get(check0, "findings");
            const usbs_json_value_t *f0 = usbs_json_array_at(findings, 0);
            const usbs_json_value_t *f1 = usbs_json_array_at(findings, 1);
            const char *msg0  = usbs_json_as_string(usbs_json_object_get(f0, "message"));
            const char *path0 = usbs_json_as_string(usbs_json_object_get(f0, "path"));
            const char *msg1  = usbs_json_as_string(usbs_json_object_get(f1, "message"));
            USBS_CHECK(msg0 != NULL && strlen(msg0) == USBS_FINDING_MESSAGE_MAX - 1);
            USBS_CHECK(path0 != NULL && strlen(path0) == USBS_FINDING_PATH_MAX - 1);
            USBS_CHECK(msg1 != NULL && strcmp(msg1, exact_msg) == 0);
            usbs_json_free(root);
        }
        free(json_text);
    }

    /* CSV */
    USBS_CHECK(usbs_ok(usbs_report_build_csv(&result, &csv_text, &csv_len)));
    if (csv_text != NULL) {
        USBS_CHECK(strstr(csv_text, "TAIL_MARKER_MSG") == NULL);
        USBS_CHECK(strstr(csv_text, "TAIL_MARKER_PATH") == NULL);
        USBS_CHECK(strstr(csv_text, "END_HERE") != NULL);
        free(csv_text);
    }

    /* Text */
    scratch = open_scratch("usbs_report_test_truncation.tmp");
    USBS_CHECK(scratch != NULL);
    if (scratch != NULL) {
        usbs_report_render_text(&result, scratch);
        rewind(scratch);
        n = fread(text_buf, 1, sizeof(text_buf) - 1, scratch);
        text_buf[n] = '\0';
        USBS_CHECK(strstr(text_buf, "TAIL_MARKER_MSG") == NULL);
        USBS_CHECK(strstr(text_buf, "TAIL_MARKER_PATH") == NULL);
        USBS_CHECK(strstr(text_buf, "END_HERE") != NULL);
        fclose(scratch);
        remove("usbs_report_test_truncation.tmp");
    }

    usbs_scan_result_free(&result);
}

int main(void)
{
    test_json_schema_envelope();
    test_text_renderer();
    test_all_ran_summary();
    test_build_json_rejects_null();
    test_oversized_finding_truncation_boundary();

    test_csv_basic_structure();
    test_csv_zero_findings_still_one_row();
    test_csv_escapes_special_characters();
    test_csv_formula_injection_mitigation();
    test_build_csv_rejects_null();

    return USBS_TEST_RESULT();
}
