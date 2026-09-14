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
#include "usbsentinel/path.h"
#include "usbsentinel/detector.h"
#include "usbsentinel/platform.h"

static void make_scratch_root(char *out, size_t cap)
{
    static usbs_bool seeded = false;
    if (!seeded) {
        srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)out);
        seeded = true;
    }
    snprintf(out, cap, "test_detectors_scratch_%08x" USBS_PATH_SEP, (unsigned)rand());
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

/* ------------------------------------------------------------------------ *
 * Phase 17.1 (ARCHITECTURE.md section 24.3): location-aware weighting of
 * the double-extension rule on an internal drive.
 * ------------------------------------------------------------------------ */

/* Runs suspicious_filename against `relative_path` on a device with `bus`,
 * accumulating into `result` (already initialized by the caller). */
static void run_tuned(usbs_bus_type_t bus, const char *relative_path, usbs_bool is_hidden,
                      usbs_check_result_t *result)
{
    static const char        volume[] = "\\\\?\\Volume{internal}\\";
    usbs_device_t             device;
    usbs_detect_context_t     detect_ctx;
    usbs_detector_file_ctx_t  file_ctx;
    usbs_dir_entry_t          entry;
    char                      full_path[1024];
    const char               *name = strrchr(relative_path, '\\');

    usbs_device_init(&device);
    device.bus_type      = bus;
    device.media_present = true;

    memset(&detect_ctx, 0, sizeof(detect_ctx));
    detect_ctx.device      = &device;
    detect_ctx.volume_path = volume;

    file_ctx.detect_ctx = &detect_ctx;
    file_ctx.result     = result;

    memset(&entry, 0, sizeof(entry));
    snprintf(entry.name, sizeof(entry.name), "%s", name != NULL ? name + 1 : relative_path);
    entry.is_hidden = is_hidden;
    snprintf(full_path, sizeof(full_path), "%s%s", volume, relative_path);

    USBS_CHECK(usbs_ok(usbs_detector_suspicious_filename.on_file(&file_ctx, full_path, &entry)));
}

/* One file, checked in isolation: returns its single finding's severity, or
 * -1 when nothing was reported. Also returns the policy counters. */
static int severity_for(usbs_bus_type_t bus, const char *relative_path, usbs_bool is_hidden,
                        usbs_u64 *out_suppressed, usbs_u64 *out_lowered, char *out_message, size_t cap)
{
    usbs_check_result_t result;
    int                 severity = -1;

    usbs_check_result_init(&result, "suspicious_filename");
    run_tuned(bus, relative_path, is_hidden, &result);
    USBS_CHECK(result.findings.count <= 1);
    if (result.findings.count == 1) {
        severity = (int)result.findings.items[0].severity;
        if (out_message != NULL) {
            snprintf(out_message, cap, "%s", result.findings.items[0].message);
        }
        /* The finding carries the relative path, not the bare name. */
        USBS_CHECK_STR_EQ(result.findings.items[0].path, relative_path);
    }
    if (out_suppressed != NULL) { *out_suppressed = result.policy_suppressed; }
    if (out_lowered != NULL)    { *out_lowered    = result.policy_lowered; }
    usbs_check_result_free(&result);
    return severity;
}

static void test_internal_drive_double_extension_weighting(void)
{
    usbs_u64 suppressed = 0;
    usbs_u64 lowered    = 0;
    char     message[USBS_FINDING_MESSAGE_MAX];

    /* Recent Items: Windows' own "<document>.lnk" shape is not reported,
     * and that is counted. */
    USBS_CHECK(severity_for(USBS_BUS_NVME,
        "Users\\alida\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CV_ALI.pdf.lnk",
        false, &suppressed, &lowered, NULL, 0) == -1);
    USBS_CHECK(suppressed == 1 && lowered == 0);

    /* ...but a disguised executable dropped into Recent Items is not a shape
     * Windows produces: still reported (drive-wide WARNING). */
    USBS_CHECK(severity_for(USBS_BUS_NVME,
        "Users\\alida\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\invoice.pdf.exe",
        false, &suppressed, &lowered, NULL, 0) == (int)USBS_SEVERITY_WARNING);
    USBS_CHECK(suppressed == 0 && lowered == 1);

    /* Dependency tree, script-type: INFO, annotated with why. */
    USBS_CHECK(severity_for(USBS_BUS_NVME,
        "Projects\\LiveGuard\\frontend\\node_modules\\es-iterator-helpers\\test\\Iterator.zip.js",
        false, &suppressed, &lowered, message, sizeof(message)) == (int)USBS_SEVERITY_INFO);
    USBS_CHECK(lowered == 1);
    USBS_CHECK(strstr(message, "double extension disguise (.zip.js)") != NULL);
    USBS_CHECK(strstr(message, "package dependency tree") != NULL);

    /* Dependency tree, native binary: never below WARNING. */
    USBS_CHECK(severity_for(USBS_BUS_NVME, "Projects\\x\\node_modules\\pkg\\invoice.pdf.exe",
        false, NULL, NULL, NULL, 0) == (int)USBS_SEVERITY_WARNING);

    /* Anywhere else on an internal drive: WARNING. */
    USBS_CHECK(severity_for(USBS_BUS_SATA, "Users\\alida\\Documents\\invoice.pdf.exe",
        false, NULL, &lowered, message, sizeof(message)) == (int)USBS_SEVERITY_WARNING);
    USBS_CHECK(lowered == 1);
    USBS_CHECK(strstr(message, "internal drive") != NULL);

    /* User-facing locations keep HIGH, unannotated and not counted. */
    USBS_CHECK(severity_for(USBS_BUS_NVME, "Users\\alida\\Downloads\\invoice.pdf.exe",
        false, &suppressed, &lowered, message, sizeof(message)) == (int)USBS_SEVERITY_HIGH);
    USBS_CHECK(suppressed == 0 && lowered == 0);
    USBS_CHECK(strstr(message, "internal drive") == NULL);
    USBS_CHECK(severity_for(USBS_BUS_NVME,
        "Users\\alida\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\resume.pdf.lnk",
        false, NULL, NULL, NULL, 0) == (int)USBS_SEVERITY_HIGH);

    /* A USB device is never tuned, in any location, including Recent Items. */
    USBS_CHECK(severity_for(USBS_BUS_USB,
        "Users\\alida\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CV_ALI.pdf.lnk",
        false, &suppressed, &lowered, NULL, 0) == (int)USBS_SEVERITY_HIGH);
    USBS_CHECK(suppressed == 0 && lowered == 0);
    USBS_CHECK(severity_for(USBS_BUS_USB, "a\\node_modules\\Iterator.zip.js",
        false, NULL, NULL, NULL, 0) == (int)USBS_SEVERITY_HIGH);
    /* Nor is an unknown bus (a bare `scan <path>`). */
    USBS_CHECK(severity_for(USBS_BUS_UNKNOWN, "a\\node_modules\\Iterator.zip.js",
        false, NULL, NULL, NULL, 0) == (int)USBS_SEVERITY_HIGH);
}

/* The other three rules have no benign producer anywhere: HIGH even in a
 * location that lowers or suppresses a double extension, and a HIGH rule
 * co-occurring with a lowered one lifts the whole finding back to HIGH. */
static void test_internal_drive_other_rules_stay_high(void)
{
    char name_path[256];
    char bidi[64];

    build_bidi_name(bidi, sizeof(bidi));
    snprintf(name_path, sizeof(name_path), "Projects\\x\\node_modules\\pkg\\%s", bidi);
    USBS_CHECK(severity_for(USBS_BUS_NVME, name_path, false, NULL, NULL, NULL, 0) ==
               (int)USBS_SEVERITY_HIGH);

    /* Hidden executable in Recent Items whose double extension is suppressed:
     * the hidden-executable rule alone still reports HIGH. */
    USBS_CHECK(severity_for(USBS_BUS_NVME,
        "Users\\alida\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CV_ALI.pdf.lnk",
        true, NULL, NULL, NULL, 0) == (int)USBS_SEVERITY_HIGH);

    /* Hidden + double extension in a dependency tree: HIGH, not INFO. */
    USBS_CHECK(severity_for(USBS_BUS_NVME, "Projects\\x\\node_modules\\pkg\\a.zip.js",
        true, NULL, NULL, NULL, 0) == (int)USBS_SEVERITY_HIGH);
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
    test_internal_drive_double_extension_weighting();
    test_internal_drive_other_rules_stay_high();
    test_suspicious_filename_invalid_args();

    return USBS_TEST_RESULT();
}
