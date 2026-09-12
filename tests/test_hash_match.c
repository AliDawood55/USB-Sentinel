/*
 * hash_match_example detector tests. This is a detector that can now load a
 * real signature file (Phase 6); these tests exist to verify the wiring
 * (env-var override, load state, the disclaimer text tracking that state,
 * the on_file pipeline), not to validate any real detection claim -
 * signature_list.c's own parsing/lookup correctness is covered separately
 * in tests/test_signature_list.c.
 *
 * Deliberately never writes real EICAR content to disk, for both the
 * fallback path and the loaded-signature-file path: doing so during Phase 5
 * development caused this machine's Windows Defender to intercept the file
 * between write and reopen - exactly what EICAR is designed to trigger, and
 * exactly the kind of interaction an automated test must not depend on. All
 * fixture content here is synthetic and safe, with hashes computed via the
 * verified SHA-256 primitive (test_hash.c), never hardcoded from memory.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "test_util.h"
#include "usbsentinel/detector.h"
#include "usbsentinel/env.h"
#include "usbsentinel/log.h"
#include "usbsentinel/platform.h"

extern const usbs_detector_t usbs_detector_hash_match;
extern const char *usbs_hash_match_lookup(usbs_u64 size_bytes, const char *hex);
extern void         usbs_hash_match_reset_for_testing(void);

#define EICAR_SHA256 "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
#define EICAR_SIZE   68

#define SIGNATURES_ENV_VAR "USBS_HASH_MATCH_SIGNATURES"

static void make_scratch_root(char *out, size_t cap)
{
    static usbs_bool seeded = false;
    if (!seeded) {
        srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)out);
        seeded = true;
    }
    snprintf(out, cap, "test_hash_match_scratch_%08x\\", (unsigned)rand());
}

static void compute_sha256_hex(const char *data, size_t len, char *out_hex)
{
    usbs_hash_ctx_t *ctx = NULL;
    unsigned char    digest[USBS_SHA256_DIGEST_SIZE];

    USBS_CHECK(usbs_ok(usbs_platform_hash_begin(&ctx)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_update(ctx, data, len)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_finish(ctx, digest, out_hex)));
}

static void run_on_file(const char *root, const char *filename, usbs_u64 size_bytes,
                        usbs_check_result_t *out_result)
{
    usbs_detect_context_t    detect_ctx;
    usbs_detector_file_ctx_t file_ctx;
    usbs_dir_entry_t          entry;
    char                       full_path[400];

    memset(&detect_ctx, 0, sizeof(detect_ctx));
    detect_ctx.volume_path = root;

    usbs_check_result_init(out_result, "hash_match_example");
    file_ctx.detect_ctx = &detect_ctx;
    file_ctx.result     = out_result;

    memset(&entry, 0, sizeof(entry));
    snprintf(entry.name, sizeof(entry.name), "%s", filename);
    entry.size_bytes = size_bytes;

    snprintf(full_path, sizeof(full_path), "%s%s", root, filename);

    USBS_CHECK(usbs_ok(usbs_detector_hash_match.on_file(&file_ctx, full_path, &entry)));
}

/* Ensures no signature-file env override is active and the cache is fresh,
 * so a test exercises the fallback (EICAR-only) path regardless of what an
 * earlier test in this same binary set up. */
static void reset_to_fallback(void)
{
    usbs_setenv(SIGNATURES_ENV_VAR, NULL);
    usbs_hash_match_reset_for_testing();
}

/* --- lookup logic, isolated from any real file content --- */

static void test_lookup_recognizes_fallback_hash(void)
{
    const char *label;
    reset_to_fallback();

    label = usbs_hash_match_lookup(EICAR_SIZE, EICAR_SHA256);
    USBS_CHECK(label != NULL);
    USBS_CHECK(label != NULL && strstr(label, "EICAR") != NULL);
}

static void test_lookup_rejects_wrong_size_for_right_hash(void)
{
    reset_to_fallback();
    /* Right hash, wrong size: must not match - size is genuinely part of
     * the key, not decoration (see also test_signature_list.c). */
    USBS_CHECK(usbs_hash_match_lookup(EICAR_SIZE + 1, EICAR_SHA256) == NULL);
}

static void test_lookup_rejects_unknown_hash(void)
{
    const char *bogus =
        "0000000000000000000000000000000000000000000000000000000000000000";
    reset_to_fallback();
    USBS_CHECK(usbs_hash_match_lookup(EICAR_SIZE, bogus) == NULL);
    USBS_CHECK(usbs_hash_match_lookup(EICAR_SIZE, "not-even-hex") == NULL);
    USBS_CHECK(usbs_hash_match_lookup(EICAR_SIZE, NULL) == NULL);
}

/* --- end-to-end pipeline, against ordinary (non-matching) content --- */

static void test_non_matching_file_no_finding(void)
{
    char                 root[260];
    char                 path[320];
    usbs_check_result_t  result;
    const char          *content = "just an ordinary document, nothing here";

    reset_to_fallback();
    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%sreadme.txt", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, content, strlen(content))));

    run_on_file(root, "readme.txt", strlen(content), &result);
    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_CHECK(result.findings.count == 0);

    usbs_check_result_free(&result);
}

/* The disclaimer (structural, not conditional on a finding) must reflect
 * the fallback state when no signature file is loaded. */
static void test_disclaimer_fallback_state(void)
{
    char                 root[260];
    char                 path[320];
    usbs_check_result_t  result;
    const char          *content = "boring";

    reset_to_fallback();
    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%sfile.dat", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, content, strlen(content))));

    run_on_file(root, "file.dat", strlen(content), &result);
    USBS_CHECK(result.findings.count == 0);
    USBS_CHECK(strstr(result.message, "NON-PRODUCTION EXAMPLE") != NULL);
    USBS_CHECK(strstr(result.message, "EICAR only") != NULL);

    usbs_check_result_free(&result);
}

/* Oversized files must never be opened at all - the size check happens
 * first, so this needs no real large file on disk. */
static void test_oversized_file_skipped(void)
{
    char                 root[260];
    usbs_check_result_t  result;

    reset_to_fallback();
    make_scratch_root(root, sizeof(root));

    run_on_file(root, "huge.bin", 128u * 1024u * 1024u, &result);
    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_CHECK(result.findings.count == 0);
    USBS_CHECK(strstr(result.message, "NON-PRODUCTION") != NULL);

    usbs_check_result_free(&result);
}

/* An unreadable file (nonexistent path) must be skipped, not fail the check -
 * per-file error isolation, same contract every other detector has. */
static void test_unreadable_file_skipped(void)
{
    char                 root[260];
    usbs_check_result_t  result;

    reset_to_fallback();
    make_scratch_root(root, sizeof(root));

    run_on_file(root, "does_not_exist.bin", 10, &result);
    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_CHECK(result.findings.count == 0);

    usbs_check_result_free(&result);
}

/* --- Phase 6: loading a real signature file via the env-var override --- */

static void test_loaded_signature_file_matches(void)
{
    char                 root[260];
    char                 sig_path[320];
    char                 fixture_path[320];
    char                 sig_content[256];
    char                 hex[USBS_SHA256_HEX_LEN + 1];
    usbs_check_result_t  result;
    const char          *marker = "USB_SENTINEL_PHASE6_TEST_MARKER_NOT_MALWARE";
    int                  n;

    compute_sha256_hex(marker, strlen(marker), hex);

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));

    n = snprintf(sig_content, sizeof(sig_content), "%s:%zu:Phase6 Test Signature\n",
                hex, strlen(marker));
    USBS_CHECK(n > 0);
    snprintf(sig_path, sizeof(sig_path), "%ssignatures.txt", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(sig_path, sig_content, (size_t)n)));

    snprintf(fixture_path, sizeof(fixture_path), "%sfixture.bin", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(fixture_path, marker, strlen(marker))));

    USBS_CHECK(usbs_ok(usbs_setenv(SIGNATURES_ENV_VAR, sig_path)));
    usbs_hash_match_reset_for_testing();

    run_on_file(root, "fixture.bin", strlen(marker), &result);
    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_CHECK(result.findings.count == 1);
    if (result.findings.count == 1) {
        USBS_CHECK(result.findings.items[0].severity == USBS_SEVERITY_HIGH);
        USBS_CHECK(strstr(result.findings.items[0].message, "Phase6 Test Signature") != NULL);
        /* A real loaded match must not carry the "demonstration match" caveat
         * that only applies to the built-in EICAR fallback entry. */
        USBS_CHECK(strstr(result.findings.items[0].message, "demonstration match") == NULL);
    }

    /* The disclaimer must reflect the loaded state, not the fallback text. */
    USBS_CHECK(strstr(result.message, "NON-PRODUCTION EXAMPLE") == NULL);
    USBS_CHECK(strstr(result.message, "1 signature(s) loaded") != NULL);
    /* Phase 9: only the filename appears, not the full path - a long
     * --signatures path previously pushed this disclaimer past
     * USBS_CHECK_MESSAGE_MAX (ARCHITECTURE.md section 14.6). Checking the
     * directory prefix is absent (not just that the filename is present,
     * which the full path would also satisfy) actually exercises that. */
    USBS_CHECK(strstr(result.message, "signatures.txt") != NULL);
    USBS_CHECK(strstr(result.message, root) == NULL);
    USBS_CHECK(strstr(result.message, "does not ship, vet, or vouch") != NULL);

    usbs_check_result_free(&result);
    reset_to_fallback();
}

static void test_loaded_signature_file_non_matching_content(void)
{
    char                 root[260];
    char                 sig_path[320];
    char                 sig_content[256];
    char                 hex[USBS_SHA256_HEX_LEN + 1];
    usbs_check_result_t  result;
    const char          *marker = "USB_SENTINEL_PHASE6_ANOTHER_MARKER";
    int                  n;

    compute_sha256_hex(marker, strlen(marker), hex);

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));

    n = snprintf(sig_content, sizeof(sig_content), "%s:%zu:Unrelated Signature\n",
                hex, strlen(marker));
    USBS_CHECK(n > 0);
    snprintf(sig_path, sizeof(sig_path), "%ssignatures.txt", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(sig_path, sig_content, (size_t)n)));

    USBS_CHECK(usbs_ok(usbs_setenv(SIGNATURES_ENV_VAR, sig_path)));
    usbs_hash_match_reset_for_testing();

    /* A file loaded, but with content that does not match anything in it. */
    {
        char path[320];
        const char *content = "nothing to see here";
        snprintf(path, sizeof(path), "%sordinary.txt", root);
        USBS_CHECK(usbs_ok(usbs_platform_write_file(path, content, strlen(content))));
        run_on_file(root, "ordinary.txt", strlen(content), &result);
    }

    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_CHECK(result.findings.count == 0);
    /* Still loaded-state disclaimer, even with nothing matched. */
    USBS_CHECK(strstr(result.message, "1 signature(s) loaded") != NULL);

    usbs_check_result_free(&result);
    reset_to_fallback();
}

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

/*
 * Phase 7: proves the size-prefilter actually fires - not just that
 * end-to-end behavior is unchanged (test_loaded_signature_file_non_matching_content
 * already covers that), but that a file whose size matches no loaded
 * signature is skipped *without ever being opened*. Captured via the debug
 * log line hash_match_on_file emits at exactly that decision point, the
 * same usbs_log_set_stream() redirection pattern test_log.c already
 * established, with TRACE enabled so a DEBUG-level line is captured.
 */
static void test_size_prefilter_skips_without_opening(void)
{
    char                 root[260];
    char                 sig_path[320];
    char                 fixture_path[320];
    char                 sig_content[256];
    char                 hex[USBS_SHA256_HEX_LEN + 1];
    usbs_check_result_t  result;
    const char          *marker = "USB_SENTINEL_PHASE7_PREFILTER_MARKER";
    int                  n;
    FILE                *scratch;
    char                 log_buf[2048];
    size_t               read_len;

    compute_sha256_hex(marker, strlen(marker), hex);

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));

    n = snprintf(sig_content, sizeof(sig_content), "%s:%zu:Prefilter Test Signature\n",
                hex, strlen(marker));
    USBS_CHECK(n > 0);
    snprintf(sig_path, sizeof(sig_path), "%ssignatures.txt", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(sig_path, sig_content, (size_t)n)));

    /* A real file whose size does NOT match the one loaded signature. */
    snprintf(fixture_path, sizeof(fixture_path), "%swrong_size.bin", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(fixture_path, "x", 1)));

    USBS_CHECK(usbs_ok(usbs_setenv(SIGNATURES_ENV_VAR, sig_path)));
    usbs_hash_match_reset_for_testing();

    scratch = open_scratch("usbs_hash_match_prefilter_test.tmp");
    USBS_CHECK(scratch != NULL);
    if (scratch == NULL) {
        reset_to_fallback();
        return;
    }

    usbs_log_set_stream(scratch);
    usbs_log_set_level(USBS_LOG_TRACE);

    /* Size 1, not strlen(marker): must be rejected by the prefilter. */
    run_on_file(root, "wrong_size.bin", 1, &result);

    usbs_log_set_level(USBS_LOG_INFO);
    usbs_log_set_stream(NULL);

    rewind(scratch);
    read_len = fread(log_buf, 1, sizeof(log_buf) - 1, scratch);
    log_buf[read_len] = '\0';
    fclose(scratch);
    remove("usbs_hash_match_prefilter_test.tmp");

    USBS_CHECK(strstr(log_buf, "skipping") != NULL);
    USBS_CHECK(strstr(log_buf, "matches no loaded signature") != NULL);

    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_CHECK(result.findings.count == 0);

    usbs_check_result_free(&result);
    reset_to_fallback();
}

/* A missing/unreadable signature file must fall back to EICAR-only
 * behavior, not fail the detector or the scan. */
static void test_missing_signature_file_falls_back(void)
{
    char                 root[260];
    char                 bogus_path[320];
    usbs_check_result_t  result;

    make_scratch_root(root, sizeof(root));
    snprintf(bogus_path, sizeof(bogus_path), "%sdoes_not_exist.txt", root);

    USBS_CHECK(usbs_ok(usbs_setenv(SIGNATURES_ENV_VAR, bogus_path)));
    usbs_hash_match_reset_for_testing();

    run_on_file(root, "anything.bin", 5, &result);
    USBS_CHECK(result.status == USBS_CHECK_RAN);
    USBS_CHECK(strstr(result.message, "NON-PRODUCTION EXAMPLE") != NULL);

    usbs_check_result_free(&result);
    reset_to_fallback();
}

static void test_invalid_args(void)
{
    reset_to_fallback();
    USBS_CHECK(usbs_detector_hash_match.on_file(NULL, "x", NULL) == USBS_ERR_INVALID_ARG);
}

int main(void)
{
    test_lookup_recognizes_fallback_hash();
    test_lookup_rejects_wrong_size_for_right_hash();
    test_lookup_rejects_unknown_hash();

    test_non_matching_file_no_finding();
    test_disclaimer_fallback_state();
    test_oversized_file_skipped();
    test_unreadable_file_skipped();

    test_loaded_signature_file_matches();
    test_loaded_signature_file_non_matching_content();
    test_size_prefilter_skips_without_opening();
    test_missing_signature_file_falls_back();

    test_invalid_args();

    return USBS_TEST_RESULT();
}
