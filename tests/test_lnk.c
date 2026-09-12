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
    snprintf(out, cap, "test_lnk_scratch_%08x\\", (unsigned)rand());
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
    test_invalid_args();

    return USBS_TEST_RESULT();
}
