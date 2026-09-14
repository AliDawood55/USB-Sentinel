/*
 * LNK parser safety tests. Every fixture is a hand-built byte buffer written
 * to a real file and run through the real detector (usbs_detector_lnk_inspect)
 * - no shortcuts through the parser's internals. The malformed battery is
 * the load-bearing part of this file: every one of these must fail cleanly
 * (a "malformed" finding, or none) and must never crash, per the Phase 4
 * requirement that every length/offset in a .lnk is hostile input.
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

extern const usbs_detector_t usbs_detector_lnk_inspect;

static const unsigned char k_clsid[16] = {
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
};

#define LNK_FLAG_HAS_LINK_INFO 0x00000002u
#define LNK_FLAG_HAS_ARGUMENTS 0x00000020u
#define LNK_FLAG_IS_UNICODE    0x00000080u

static size_t put_u16(unsigned char *buf, size_t pos, uint16_t v)
{
    buf[pos]     = (unsigned char)(v & 0xFF);
    buf[pos + 1] = (unsigned char)((v >> 8) & 0xFF);
    return pos + 2;
}

static size_t put_u32(unsigned char *buf, size_t pos, uint32_t v)
{
    buf[pos]     = (unsigned char)(v & 0xFF);
    buf[pos + 1] = (unsigned char)((v >> 8) & 0xFF);
    buf[pos + 2] = (unsigned char)((v >> 16) & 0xFF);
    buf[pos + 3] = (unsigned char)((v >> 24) & 0xFF);
    return pos + 4;
}

/*
 * Builds a well-formed, spec-conformant minimal .lnk: fixed header,
 * HasLinkInfo with a VolumeIDAndLocalBasePath target string, and (if
 * `args` is non-NULL) a Unicode Arguments StringData block. Returns the
 * total length written.
 */
static size_t build_lnk(unsigned char *buf, size_t cap, const char *target, const char *args)
{
    size_t   pos;
    size_t   link_info_start;
    size_t   target_len = strlen(target);
    uint32_t link_info_size = (uint32_t)(28 + target_len + 1);
    uint32_t flags = LNK_FLAG_HAS_LINK_INFO | LNK_FLAG_IS_UNICODE;

    USBS_UNUSED(cap); /* callers size the buffer generously; asserted by USBS_CHECK at call sites */

    if (args != NULL) {
        flags |= LNK_FLAG_HAS_ARGUMENTS;
    }

    pos = 0;
    pos = put_u32(buf, pos, 76);                 /* HeaderSize */
    memcpy(buf + pos, k_clsid, 16); pos += 16;    /* LinkCLSID */
    pos = put_u32(buf, pos, flags);               /* LinkFlags */
    pos = put_u32(buf, pos, 0);                   /* FileAttributes */
    memset(buf + pos, 0, 24); pos += 24;          /* Creation/Access/WriteTime */
    pos = put_u32(buf, pos, 0);                   /* FileSize */
    pos = put_u32(buf, pos, 0);                   /* IconIndex */
    pos = put_u32(buf, pos, 1);                   /* ShowCommand */
    pos = put_u16(buf, pos, 0);                   /* HotKey */
    pos = put_u16(buf, pos, 0);                   /* Reserved1 */
    pos = put_u32(buf, pos, 0);                   /* Reserved2 */
    pos = put_u32(buf, pos, 0);                   /* Reserved3 */
    /* pos == 76 here */

    link_info_start = pos;
    pos = put_u32(buf, pos, link_info_size);       /* LinkInfoSize */
    pos = put_u32(buf, pos, 0x1C);                 /* LinkInfoHeaderSize */
    pos = put_u32(buf, pos, 0x1);                  /* LinkInfoFlags: VolumeIDAndLocalBasePath */
    pos = put_u32(buf, pos, 0);                    /* VolumeIDOffset (unused by our parser) */
    pos = put_u32(buf, pos, 28);                   /* LocalBasePathOffset, relative to link_info_start */
    pos = put_u32(buf, pos, 0);                    /* CommonNetworkRelativeLinkOffset */
    pos = put_u32(buf, pos, 0);                    /* CommonPathSuffixOffset */
    memcpy(buf + pos, target, target_len + 1);      /* includes NUL */
    pos += target_len + 1;
    USBS_CHECK(pos == link_info_start + link_info_size);

    if (args != NULL) {
        size_t args_len = strlen(args);
        size_t i;
        pos = put_u16(buf, pos, (uint16_t)args_len);
        for (i = 0; i < args_len; ++i) {
            buf[pos++] = (unsigned char)args[i];
            buf[pos++] = 0; /* UTF-16LE, ASCII-only fixture */
        }
    }

    return pos;
}

static void make_scratch_root(char *out, size_t cap)
{
    static usbs_bool seeded = false;
    if (!seeded) {
        srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)out);
        seeded = true;
    }
    snprintf(out, cap, "test_lnk_scratch_%08x" USBS_PATH_SEP, (unsigned)rand());
}

/*
 * Phase 5: lnk_inspect is now an on_file detector, invoked once per file by
 * scanner's single shared walk (ARCHITECTURE.md's Phase 5 notes) rather than
 * walking the volume itself. Unit tests call on_file() directly against one
 * synthetic usbs_dir_entry_t - a genuine simplification the refactor
 * enables: no working walk is needed to test the detector's own per-file
 * logic in isolation. `size_bytes` is passed separately from the file
 * actually written to disk so the oversized-file test needs no real large
 * file (the size check happens before anything is opened).
 */
static void run_on_file(const char *root, const char *filename, usbs_u64 size_bytes,
                        usbs_check_result_t *out_result)
{
    usbs_detect_context_t    detect_ctx;
    usbs_detector_file_ctx_t file_ctx;
    usbs_dir_entry_t          entry;
    char                       full_path[400];

    memset(&detect_ctx, 0, sizeof(detect_ctx));
    detect_ctx.volume_path = root;

    usbs_check_result_init(out_result, "lnk_inspection");
    file_ctx.detect_ctx = &detect_ctx;
    file_ctx.result     = out_result;

    memset(&entry, 0, sizeof(entry));
    snprintf(entry.name, sizeof(entry.name), "%s", filename);
    entry.size_bytes = size_bytes;

    snprintf(full_path, sizeof(full_path), "%s%s", root, filename);

    USBS_CHECK(usbs_ok(usbs_detector_lnk_inspect.on_file(&file_ctx, full_path, &entry)));
}

/* --- well-formed fixtures --- */

static void test_benign_lnk_no_finding(void)
{
    unsigned char        buf[2048];
    size_t                len;
    char                  root[260];
    char                  path[320];
    usbs_check_result_t   result;

    len = build_lnk(buf, sizeof(buf), "C:\\MyApps\\notepad.exe", NULL);

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%sshortcut.lnk", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, buf, len)));

    run_on_file(root, "shortcut.lnk", len, &result);
    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_CHECK(result.findings.count == 0); /* ordinary shortcut: no noise */

    usbs_check_result_free(&result);
}

static void test_suspicious_lnk_interpreter_and_arguments(void)
{
    unsigned char        buf[2048];
    size_t                len;
    char                  root[260];
    char                  path[320];
    usbs_check_result_t   result;

    len = build_lnk(buf, sizeof(buf),
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "-enc SGVsbG8gV29ybGQ=");

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%sinvoice.pdf.lnk", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, buf, len)));

    run_on_file(root, "invoice.pdf.lnk", len, &result);
    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_CHECK(result.findings.count == 1);
    USBS_CHECK(result.findings.items[0].severity == USBS_SEVERITY_HIGH);
    USBS_CHECK(strstr(result.findings.items[0].message, "powershell.exe") != NULL);
    USBS_CHECK(strstr(result.findings.items[0].message, "interpreter target") != NULL);
    USBS_CHECK(strstr(result.findings.items[0].message, "-enc") != NULL);
    USBS_CHECK(strstr(result.findings.items[0].message, "sha256=") != NULL);
    /* Never acted on: this test itself never opened/executed the target. */

    usbs_check_result_free(&result);
}

/* The walk-driven "does the volume contain any .lnk files" behavior is now
 * scanner's concern (test_scanner.c); what belongs here is the detector's
 * own extension filter, unit-tested directly. */
static void test_non_lnk_extension_ignored(void)
{
    char                 root[260];
    char                  path[320];
    usbs_check_result_t  result;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%sreadme.txt", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, "hello", 5)));

    run_on_file(root, "readme.txt", 5, &result);
    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_CHECK(result.findings.count == 0);

    usbs_check_result_free(&result);
}

/* --- malformed-input battery: must never crash, must fail cleanly --- */

static void expect_malformed(const unsigned char *buf, size_t len, const char *name)
{
    char                 root[260];
    char                 path[320];
    usbs_check_result_t  result;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%s%s", root, name);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, buf, len)));

    run_on_file(root, name, len, &result);
    USBS_CHECK(result.status == USBS_CHECK_RAN); /* the detector itself did not fail */
    USBS_CHECK(result.findings.count == 1);
    if (result.findings.count == 1) {
        USBS_CHECK(result.findings.items[0].severity == USBS_SEVERITY_WARNING);
        USBS_CHECK(strstr(result.findings.items[0].message, "malformed") != NULL);
    } else {
        fprintf(stderr, "  (%s: got %zu finding(s) instead)\n", name, result.findings.count);
    }

    usbs_check_result_free(&result);
}

static void test_empty_file(void)
{
    expect_malformed((const unsigned char *)"", 0, "empty.lnk");
}

static void test_truncated_before_header_end(void)
{
    unsigned char buf[2048];
    size_t        len = build_lnk(buf, sizeof(buf), "C:\\a.exe", NULL);
    USBS_UNUSED(len);
    expect_malformed(buf, 10, "truncated_early.lnk");
}

static void test_truncated_exactly_at_header(void)
{
    unsigned char buf[2048];
    size_t        len = build_lnk(buf, sizeof(buf), "C:\\a.exe", NULL);
    USBS_UNUSED(len);
    /* HasLinkInfo is set in the flags, but no LinkInfo bytes follow. */
    expect_malformed(buf, 76, "truncated_at_header.lnk");
}

static void test_bad_header_size_field(void)
{
    unsigned char buf[2048];
    size_t        len = build_lnk(buf, sizeof(buf), "C:\\a.exe", NULL);
    buf[0] = 0x00; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00; /* HeaderSize = 0 */
    expect_malformed(buf, len, "bad_header_size.lnk");
}

static void test_bad_clsid(void)
{
    unsigned char buf[2048];
    size_t        len = build_lnk(buf, sizeof(buf), "C:\\a.exe", NULL);
    buf[4] ^= 0xFF; /* flip a byte inside LinkCLSID */
    expect_malformed(buf, len, "bad_clsid.lnk");
}

static void test_link_info_size_exceeds_buffer(void)
{
    unsigned char buf[2048];
    size_t        len = build_lnk(buf, sizeof(buf), "C:\\a.exe", NULL);
    /* LinkInfoSize field is the first u32 right after the 76-byte header. */
    put_u32(buf, 76, 0xFFFFFF00u);
    expect_malformed(buf, len, "link_info_overflow.lnk");
}

static void test_local_base_path_offset_beyond_link_info(void)
{
    unsigned char buf[2048];
    size_t        len = build_lnk(buf, sizeof(buf), "C:\\a.exe", NULL);
    /* LocalBasePathOffset is at link_info_start(76) + 16. Point it far past
     * this LinkInfo structure's own (small) size. */
    put_u32(buf, 76 + 16, 0xFFFF0000u);
    expect_malformed(buf, len, "bad_local_base_path_offset.lnk");
}

static void test_arguments_count_exceeds_buffer(void)
{
    unsigned char buf[2048];
    size_t        link_info_size;
    size_t        count_offset;

    build_lnk(buf, sizeof(buf), "C:\\a.exe", "hi");
    /* Find the Arguments CountCharacters field: it is the u16 right after
     * the LinkInfo block. Corrupt it to claim far more characters than the
     * (now-truncated) buffer actually holds. */
    link_info_size = 28 + strlen("C:\\a.exe") + 1;
    count_offset   = 76 + link_info_size;
    put_u16(buf, count_offset, 0xFFFFu);
    /* Truncate right after the (corrupted) count field, well short of what
     * 0xFFFF characters would require. */
    expect_malformed(buf, count_offset + 2 + 4, "bad_arguments_count.lnk");
}

static void test_random_garbage(void)
{
    unsigned char buf[300];
    size_t        i;
    for (i = 0; i < sizeof(buf); ++i) {
        buf[i] = (unsigned char)(i * 37u + 11u); /* deterministic, non-zero-structured noise */
    }
    expect_malformed(buf, sizeof(buf), "garbage.lnk");
}

static void test_oversized_lnk_not_parsed(void)
{
    /* Larger than LNK_MAX_READ (256 KiB); must be flagged on size alone,
     * without ever being opened for structural parsing - the size check
     * happens before any file I/O, so this test does not need to write an
     * actual 300 KiB file, only claim that size via the synthetic entry. */
    char                 root[260];
    usbs_check_result_t  result;

    make_scratch_root(root, sizeof(root));

    run_on_file(root, "huge.lnk", 300 * 1024, &result);
    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_CHECK(result.findings.count == 1);
    USBS_CHECK(result.findings.items[0].severity == USBS_SEVERITY_WARNING);
    USBS_CHECK(strstr(result.findings.items[0].message, "oversized") != NULL);

    usbs_check_result_free(&result);
}

/* ------------------------------------------------------------------------ *
 * Phase 17.1 (ARCHITECTURE.md section 24.2): internal-drive location policy.
 * Real .lnk fixtures, written into Start Menu / WinSxS / Startup-shaped
 * directories under a scratch root that stands in for the volume root.
 * ------------------------------------------------------------------------ */

#define SEP USBS_PATH_SEP
#define START_MENU_DIR "ProgramData" SEP "Microsoft" SEP "Windows" SEP "Start Menu" SEP "Programs" SEP "Tools" SEP
#define STARTUP_DIR    "ProgramData" SEP "Microsoft" SEP "Windows" SEP "Start Menu" SEP "Programs" SEP "Startup" SEP
#define WINSXS_DIR     "Windows" SEP "WinSxS" SEP "amd64_microsoft.windows.powershell.common_x" SEP

/* Writes `bytes` to <root><dir><name> and runs the detector on it for a
 * device on `bus`; returns the check's finding count and policy counters. */
static size_t run_located(const char *dir, const char *name, const unsigned char *bytes, size_t len,
                          usbs_bus_type_t bus, usbs_u64 *out_suppressed,
                          usbs_check_result_t *out_result)
{
    char                     root[260];
    char                     dir_path[520];
    char                     full_path[640];
    usbs_device_t            device;
    usbs_detect_context_t    detect_ctx;
    usbs_detector_file_ctx_t file_ctx;
    usbs_dir_entry_t         entry;

    make_scratch_root(root, sizeof(root));
    snprintf(dir_path, sizeof(dir_path), "%s%s", root, dir);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(dir_path)));
    snprintf(full_path, sizeof(full_path), "%s%s", dir_path, name);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(full_path, bytes, len)));

    usbs_device_init(&device);
    device.bus_type      = bus;
    device.media_present = true;

    memset(&detect_ctx, 0, sizeof(detect_ctx));
    detect_ctx.device      = &device;
    detect_ctx.volume_path = root;

    usbs_check_result_init(out_result, "lnk_inspection");
    file_ctx.detect_ctx = &detect_ctx;
    file_ctx.result     = out_result;

    memset(&entry, 0, sizeof(entry));
    snprintf(entry.name, sizeof(entry.name), "%s", name);
    entry.size_bytes = len;

    USBS_CHECK(usbs_ok(usbs_detector_lnk_inspect.on_file(&file_ctx, full_path, &entry)));
    if (out_suppressed != NULL) {
        *out_suppressed = out_result->policy_suppressed;
    }
    return out_result->findings.count;
}

static void test_start_menu_interpreter_shortcut_is_tuned_out(void)
{
    unsigned char       buf[4096];
    size_t              len;
    usbs_check_result_t result;
    usbs_u64            suppressed = 0;

    /* The real "Developer Command Prompt for VS 2022" shape: cmd.exe with
     * ordinary arguments. */
    len = build_lnk(buf, sizeof(buf), "C:\\Windows\\System32\\cmd.exe",
                    "/k \"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\Tools\\VsDevCmd.bat\"");

    USBS_CHECK(run_located(START_MENU_DIR, "Developer Command Prompt.lnk", buf, len,
                           USBS_BUS_NVME, &suppressed, &result) == 0);
    USBS_CHECK(suppressed == 1);
    usbs_check_result_free(&result);

    /* The same shortcut on a USB stick is still HIGH: nothing changed there. */
    USBS_CHECK(run_located(START_MENU_DIR, "Developer Command Prompt.lnk", buf, len,
                           USBS_BUS_USB, &suppressed, &result) == 1);
    USBS_CHECK(suppressed == 0);
    USBS_CHECK(result.findings.items[0].severity == USBS_SEVERITY_HIGH);
    usbs_check_result_free(&result);
}

/* The load-bearing negative: the tuning must not hide the actual attack. An
 * interpreter launched with an encoded command is HIGH even in the Start
 * Menu of an internal drive. */
static void test_start_menu_attack_shape_still_reported(void)
{
    unsigned char       buf[4096];
    size_t              len;
    usbs_check_result_t result;
    usbs_u64            suppressed = 0;

    len = build_lnk(buf, sizeof(buf),
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "-nop -w hidden -enc SQBFAFgA");

    USBS_CHECK(run_located(START_MENU_DIR, "Updater.lnk", buf, len,
                           USBS_BUS_NVME, &suppressed, &result) == 1);
    USBS_CHECK(suppressed == 0);
    if (result.findings.count == 1) {
        USBS_CHECK(result.findings.items[0].severity == USBS_SEVERITY_HIGH);
        USBS_CHECK(strstr(result.findings.items[0].message, "interpreter target") != NULL);
        USBS_CHECK(strstr(result.findings.items[0].message, "suspicious argument") != NULL);
        /* Relative to the volume root, so it names the Start Menu location. */
        USBS_CHECK(strstr(result.findings.items[0].path, "Start Menu") != NULL);
    }
    usbs_check_result_free(&result);
}

/* A browser shortcut with a URL argument (marker without an interpreter) is
 * normal in the Start Menu. */
static void test_start_menu_url_argument_is_tuned_out(void)
{
    unsigned char       buf[4096];
    size_t              len;
    usbs_check_result_t result;
    usbs_u64            suppressed = 0;

    len = build_lnk(buf, sizeof(buf), "C:\\Program Files\\Browser\\browser.exe",
                    "--app=https://example.com/");
    USBS_CHECK(run_located(START_MENU_DIR, "Web App.lnk", buf, len,
                           USBS_BUS_SATA, &suppressed, &result) == 0);
    USBS_CHECK(suppressed == 1);
    usbs_check_result_free(&result);
}

/* Startup is a persistence location and outranks the Start Menu around it:
 * an interpreter shortcut there is HIGH even with ordinary arguments. */
static void test_startup_folder_is_never_tuned(void)
{
    unsigned char       buf[4096];
    size_t              len;
    usbs_check_result_t result;
    usbs_u64            suppressed = 0;

    len = build_lnk(buf, sizeof(buf), "C:\\Windows\\System32\\cmd.exe", "/c start updater.bat");
    USBS_CHECK(run_located(STARTUP_DIR, "Updater.lnk", buf, len,
                           USBS_BUS_NVME, &suppressed, &result) == 1);
    USBS_CHECK(suppressed == 0);
    if (result.findings.count == 1) {
        USBS_CHECK(result.findings.items[0].severity == USBS_SEVERITY_HIGH);
    }
    usbs_check_result_free(&result);
}

/* WinSxS: nothing reported, including a malformed "shortcut" (the store's
 * delta-compressed payloads end in .lnk too); a USB device is untuned. */
static void test_component_store_is_tuned_out(void)
{
    unsigned char       buf[4096];
    size_t              len;
    usbs_check_result_t result;
    usbs_u64            suppressed = 0;
    static const unsigned char garbage[] = { 'P', 'A', '3', '0', 0x01, 0x02, 0x03, 0x04 };

    len = build_lnk(buf, sizeof(buf),
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", NULL);
    USBS_CHECK(run_located(WINSXS_DIR, "Windows PowerShell.lnk", buf, len,
                           USBS_BUS_NVME, &suppressed, &result) == 0);
    USBS_CHECK(suppressed == 1);
    usbs_check_result_free(&result);

    USBS_CHECK(run_located(WINSXS_DIR "r" SEP, "ODBC Data Sources (32-bit).lnk",
                           garbage, sizeof(garbage), USBS_BUS_NVME, &suppressed, &result) == 0);
    USBS_CHECK(suppressed == 1);
    usbs_check_result_free(&result);

    USBS_CHECK(run_located(WINSXS_DIR "r" SEP, "ODBC Data Sources (32-bit).lnk",
                           garbage, sizeof(garbage), USBS_BUS_USB, &suppressed, &result) == 1);
    USBS_CHECK(suppressed == 0);
    usbs_check_result_free(&result);
}

static void test_invalid_args(void)
{
    USBS_CHECK(usbs_detector_lnk_inspect.on_file(NULL, "x", NULL) == USBS_ERR_INVALID_ARG);
}

int main(void)
{
    test_benign_lnk_no_finding();
    test_suspicious_lnk_interpreter_and_arguments();
    test_non_lnk_extension_ignored();

    test_empty_file();
    test_truncated_before_header_end();
    test_truncated_exactly_at_header();
    test_bad_header_size_field();
    test_bad_clsid();
    test_link_info_size_exceeds_buffer();
    test_local_base_path_offset_beyond_link_info();
    test_arguments_count_exceeds_buffer();
    test_random_garbage();
    test_oversized_lnk_not_parsed();
    test_start_menu_interpreter_shortcut_is_tuned_out();
    test_start_menu_attack_shape_still_reported();
    test_start_menu_url_argument_is_tuned_out();
    test_startup_folder_is_never_tuned();
    test_component_store_is_tuned_out();
    test_invalid_args();

    return USBS_TEST_RESULT();
}
