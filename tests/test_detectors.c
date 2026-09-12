/*
 * Detector tests run the real autorun.inf detector against a scratch
 * directory standing in for a volume root - detectors only ever see a plain
 * directory path, so no USB hardware or fake filesystem seam is needed.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "test_util.h"
#include "usbsentinel/detector.h"
#include "usbsentinel/platform.h"

static void make_scratch_root(char *out, size_t cap)
{
    static usbs_bool seeded = false;
    if (!seeded) {
        srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)out);
        seeded = true;
    }
    snprintf(out, cap, "test_detectors_scratch_%08x\\", (unsigned)rand());
}

static void test_registry_shape(void)
{
    size_t count = usbs_detector_count();
    size_t i;

    USBS_CHECK(count == 4);
    for (i = 0; i < count; ++i) {
        const usbs_detector_t *det = usbs_detector_at(i);
        USBS_CHECK(det != NULL);
        USBS_CHECK(det->id != NULL);
        /* Exactly one of run/on_file is set - the Phase 5 interface split
         * (ARCHITECTURE.md's Phase 5 notes; detector.h documents this as a
         * convention, not runtime-enforced machinery). */
        USBS_CHECK((det->run != NULL) != (det->on_file != NULL));
    }
    USBS_CHECK_STR_EQ(usbs_detector_at(0)->id, "autorun_inspection");
    USBS_CHECK(usbs_detector_at(0)->run != NULL);
    USBS_CHECK_STR_EQ(usbs_detector_at(1)->id, "suspicious_filename");
    USBS_CHECK(usbs_detector_at(1)->on_file != NULL);
    USBS_CHECK_STR_EQ(usbs_detector_at(2)->id, "lnk_inspection");
    USBS_CHECK(usbs_detector_at(2)->on_file != NULL);
    USBS_CHECK_STR_EQ(usbs_detector_at(3)->id, "hash_match_example");
    USBS_CHECK(usbs_detector_at(3)->on_file != NULL);

    /* Out of range must return NULL, not read past the array. */
    USBS_CHECK(usbs_detector_at(count) == NULL);
    USBS_CHECK(usbs_detector_at(9999) == NULL);
}

static const usbs_detector_t *autorun_detector(void)
{
    return usbs_detector_at(0);
}

extern const usbs_detector_t usbs_detector_suspicious_filename;

static void test_no_autorun_present(void)
{
    char                   root[260];
    usbs_detect_context_t  ctx;
    usbs_check_result_t    result;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));

    memset(&ctx, 0, sizeof(ctx));
    ctx.volume_path = root;

    USBS_CHECK(usbs_ok(autorun_detector()->run(&ctx, &result)));
    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_CHECK(result.findings.count == 0);

    usbs_check_result_free(&result);
}

static void test_autorun_with_launch_directive(void)
{
    char                   root[260];
    char                   path[300];
    usbs_detect_context_t  ctx;
    usbs_check_result_t    result;
    const char             content[] = "[autorun]\r\nopen=setup.exe\r\n";

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%sautorun.inf", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, content, strlen(content))));

    memset(&ctx, 0, sizeof(ctx));
    ctx.volume_path = root;

    USBS_CHECK(usbs_ok(autorun_detector()->run(&ctx, &result)));
    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_CHECK(result.findings.count == 1);
    USBS_CHECK(strstr(result.findings.items[0].message, "open=") != NULL);
    USBS_CHECK_STR_EQ(result.findings.items[0].path, "autorun.inf");
    USBS_CHECK(result.findings.items[0].severity == USBS_SEVERITY_WARNING);

    usbs_check_result_free(&result);
}

static void test_autorun_case_insensitive_directive(void)
{
    char                   root[260];
    char                   path[300];
    usbs_detect_context_t  ctx;
    usbs_check_result_t    result;
    const char             content[] = "[AutoRun]\r\nSHELLEXECUTE=run.exe\r\n";

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%sautorun.inf", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, content, strlen(content))));

    memset(&ctx, 0, sizeof(ctx));
    ctx.volume_path = root;

    USBS_CHECK(usbs_ok(autorun_detector()->run(&ctx, &result)));
    USBS_CHECK(result.findings.count == 1);
    USBS_CHECK(strstr(result.findings.items[0].message, "shellexecute=") != NULL);
    USBS_CHECK(result.findings.items[0].severity == USBS_SEVERITY_WARNING);

    usbs_check_result_free(&result);
}

/*
 * Phase 14: the detector must find autorun.inf by its own case-insensitive
 * rule, not by inheriting one from the filesystem.
 *
 * Before this, the detector opened "<volume>autorun.inf" directly, which
 * matches AUTORUN.INF only because NTFS and FAT are case-insensitive. On
 * ext4 the identical stick would have reported nothing - and AUTORUN.INF in
 * caps is the historically common spelling in exactly the malware this
 * detector exists to find.
 *
 * On Windows this test still catches a regression even though the open
 * would succeed either way, because it asserts the *reported* path: NTFS
 * preserves the case it was created with, so a detector that hardcodes the
 * canonical spelling reports "autorun.inf" where the volume really holds
 * "AUTORUN.INF". On Linux it additionally exercises the lookup itself.
 */
static void test_autorun_uppercase_filename(void)
{
    char                   root[260];
    char                   path[300];
    usbs_detect_context_t  ctx;
    usbs_check_result_t    result;
    const char             content[] = "[autorun]\r\nopen=evil.exe\r\n";

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%sAUTORUN.INF", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, content, strlen(content))));

    memset(&ctx, 0, sizeof(ctx));
    ctx.volume_path = root;

    USBS_CHECK(usbs_ok(autorun_detector()->run(&ctx, &result)));
    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_REQUIRE(result.findings.count == 1);
    USBS_CHECK(strstr(result.findings.items[0].message, "open=") != NULL);
    USBS_CHECK(result.findings.items[0].severity == USBS_SEVERITY_WARNING);

    /* The spelling that is actually on the volume, not the canonical one. */
    USBS_CHECK_STR_EQ(result.findings.items[0].path, "AUTORUN.INF");

    usbs_check_result_free(&result);
}

/* A mixed-case spelling must resolve too - the rule is case-insensitive
 * matching, not a two-entry lowercase/uppercase lookup table. */
static void test_autorun_mixed_case_filename(void)
{
    char                   root[260];
    char                   path[300];
    usbs_detect_context_t  ctx;
    usbs_check_result_t    result;
    const char             content[] = "[autorun]\r\nicon=icon.ico\r\n";

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%sAutoRun.Inf", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, content, strlen(content))));

    memset(&ctx, 0, sizeof(ctx));
    ctx.volume_path = root;

    USBS_CHECK(usbs_ok(autorun_detector()->run(&ctx, &result)));
    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_REQUIRE(result.findings.count == 1);
    USBS_CHECK(result.findings.items[0].severity == USBS_SEVERITY_INFO);
    USBS_CHECK_STR_EQ(result.findings.items[0].path, "AutoRun.Inf");

    usbs_check_result_free(&result);
}

static void test_autorun_present_without_directive(void)
{
    char                   root[260];
    char                   path[300];
    usbs_detect_context_t  ctx;
    usbs_check_result_t    result;
    const char             content[] = "[autorun]\r\nicon=icon.ico\r\n";

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%sautorun.inf", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, content, strlen(content))));

    memset(&ctx, 0, sizeof(ctx));
    ctx.volume_path = root;

    USBS_CHECK(usbs_ok(autorun_detector()->run(&ctx, &result)));
    USBS_CHECK(result.findings.count == 1);
    USBS_CHECK(strstr(result.findings.items[0].message, "no launch command") != NULL);
    USBS_CHECK(result.findings.items[0].severity == USBS_SEVERITY_INFO);

    usbs_check_result_free(&result);
}

static void test_invalid_args(void)
{
    usbs_check_result_t result;
    USBS_CHECK(autorun_detector()->run(NULL, &result) == USBS_ERR_INVALID_ARG);
}

/* ------------------------------------------------------------------------ *
 * suspicious_filename - metadata-only, so fixtures are just filenames
 * (content is irrelevant and left empty).
 * ------------------------------------------------------------------------ */

static const usbs_finding_t *only_finding(const usbs_check_result_t *result)
{
    USBS_CHECK(result->findings.count == 1);
    return (result->findings.count == 1) ? &result->findings.items[0] : NULL;
}

/*
 * Phase 5: suspicious_filename is now an on_file detector, invoked once per
 * file by scanner's single shared walk (ARCHITECTURE.md's Phase 5 notes)
 * rather than walking the volume itself. Since it is metadata-only (never
 * opens a file's content - the whole point of this detector), its unit
 * tests need no real file on disk at all: a synthetic usbs_dir_entry_t with
 * just a name (and, for the hidden-executable case, is_hidden) is a
 * complete, faithful fixture.
 */
static void run_on_entry(const char *name, usbs_bool is_hidden, usbs_check_result_t *out_result)
{
    usbs_detect_context_t    detect_ctx;
    usbs_detector_file_ctx_t file_ctx;
    usbs_dir_entry_t          entry;

    memset(&detect_ctx, 0, sizeof(detect_ctx));
    detect_ctx.volume_path = "\\\\?\\Volume{test}\\";

    usbs_check_result_init(out_result, "suspicious_filename");
    file_ctx.detect_ctx = &detect_ctx;
    file_ctx.result     = out_result;

    memset(&entry, 0, sizeof(entry));
    snprintf(entry.name, sizeof(entry.name), "%s", name);
    entry.is_hidden = is_hidden;

    USBS_CHECK(usbs_ok(usbs_detector_suspicious_filename.on_file(&file_ctx, name, &entry)));
}

static void test_double_extension_disguise(void)
{
    usbs_check_result_t  result;
    const usbs_finding_t *finding;

    run_on_entry("invoice.pdf.exe", false, &result);
    finding = only_finding(&result);
    if (finding != NULL) {
        USBS_CHECK(finding->severity == USBS_SEVERITY_HIGH);
        USBS_CHECK(strstr(finding->message, "double extension") != NULL);
        USBS_CHECK_STR_EQ(finding->path, "invoice.pdf.exe");
    }

    usbs_check_result_free(&result);
}

/* U+202E RIGHT-TO-LEFT OVERRIDE (E2 80 AE in UTF-8) - the classic trick that
 * makes "invoice<RLO>cod.exe" display with the visible extension reversed. */
static void build_bidi_name(char *out, size_t cap)
{
    const unsigned char bidi[3] = { 0xE2, 0x80, 0xAE };
    size_t pos;

    snprintf(out, cap, "invoice");
    pos = strlen(out);
    if (pos + 3 < cap) {
        memcpy(out + pos, bidi, 3);
        pos += 3;
        out[pos] = '\0';
    }
    snprintf(out + pos, cap - pos, "cod.exe");
}

static void test_bidi_override_filename(void)
{
    char                 name[64];
    usbs_check_result_t  result;
    const usbs_finding_t *finding;

    build_bidi_name(name, sizeof(name));

    run_on_entry(name, false, &result);
    finding = only_finding(&result);
    if (finding != NULL) {
        USBS_CHECK(finding->severity == USBS_SEVERITY_HIGH);
        USBS_CHECK(strstr(finding->message, "bidi-override") != NULL);
    }

    usbs_check_result_free(&result);
}

static void test_space_padding_before_hidden_extension(void)
{
    usbs_check_result_t  result;
    const usbs_finding_t *finding;
    /* "resume.pdf" then a long run of spaces, then the real extension. */
    const char          *name = "resume.pdf                                   .exe";

    run_on_entry(name, false, &result);
    finding = only_finding(&result);
    if (finding != NULL) {
        USBS_CHECK(finding->severity == USBS_SEVERITY_HIGH);
        USBS_CHECK(strstr(finding->message, "space padding") != NULL);
    }

    usbs_check_result_free(&result);
}

static void test_hidden_executable(void)
{
    usbs_check_result_t  result;
    const usbs_finding_t *finding;

    run_on_entry("svc.exe", true, &result);
    finding = only_finding(&result);
    if (finding != NULL) {
        USBS_CHECK(finding->severity == USBS_SEVERITY_HIGH);
        USBS_CHECK(strstr(finding->message, "hidden") != NULL);
    }

    usbs_check_result_free(&result);
}

/* Negative fixtures: ordinary files must never be flagged - all accumulated
 * into one check_result, matching how scanner's shared walk calls on_file
 * repeatedly against the same in-progress result for every file. */
static void test_normal_files_no_findings(void)
{
    static const char *const names[] = {
        "readme.txt", "photo.jpg", "notes.docx", "archive.zip",
        "setup.exe", /* a lone executable, no disguise pattern, is not itself flagged */
    };
    usbs_detect_context_t detect_ctx;
    usbs_check_result_t   result;
    size_t                i;

    memset(&detect_ctx, 0, sizeof(detect_ctx));
    detect_ctx.volume_path = "\\\\?\\Volume{test}\\";
    usbs_check_result_init(&result, "suspicious_filename");

    for (i = 0; i < USBS_ARRAY_LEN(names); ++i) {
        usbs_detector_file_ctx_t file_ctx;
        usbs_dir_entry_t          entry;

        memset(&entry, 0, sizeof(entry));
        snprintf(entry.name, sizeof(entry.name), "%s", names[i]);
        file_ctx.detect_ctx = &detect_ctx;
        file_ctx.result     = &result;

        USBS_CHECK(usbs_ok(
            usbs_detector_suspicious_filename.on_file(&file_ctx, names[i], &entry)));
    }

    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_CHECK(result.findings.count == 0);

    usbs_check_result_free(&result);
}

static void test_suspicious_filename_invalid_args(void)
{
    USBS_CHECK(usbs_detector_suspicious_filename.on_file(NULL, "x", NULL) ==
              USBS_ERR_INVALID_ARG);
}

int main(void)
{
    test_registry_shape();
    test_no_autorun_present();
    test_autorun_with_launch_directive();
    test_autorun_case_insensitive_directive();
    test_autorun_uppercase_filename();
    test_autorun_mixed_case_filename();
    test_autorun_present_without_directive();
    test_invalid_args();

    test_double_extension_disguise();
    test_bidi_override_filename();
    test_space_padding_before_hidden_extension();
    test_hidden_executable(); /* no longer Win32-only: pure synthetic entry, no real attribute set */
    test_normal_files_no_findings();
    test_suspicious_filename_invalid_args();

    return USBS_TEST_RESULT();
}
