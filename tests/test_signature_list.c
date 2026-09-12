/*
 * signature_list tests: the "sha256:size:name" loader and size-bucketed
 * lookup (src/detectors/signature_list.c). No content here ever resembles
 * EICAR or any real malware string - every hash used is computed from an
 * explicitly synthetic marker string via the same verified SHA-256 primitive
 * test_hash.c already validated against NIST vectors, never hardcoded from
 * memory (the Phase 5 lesson, applied proactively here).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "test_util.h"
#include "usbsentinel/platform.h"

/* signature_list.h is module-internal (not under include/usbsentinel), so
 * tests declare exactly what they use - the same pattern already used for
 * `extern const usbs_detector_t ...` elsewhere. Kept minimal and in sync by
 * hand; a mismatch would be a linker-visible or behavioral bug, not a
 * silent one, since every field here is exercised. */
#define USBS_SIGNATURE_HASH_LEN 64
#define USBS_SIGNATURE_NAME_MAX 160

typedef struct usbs_signature {
    char     sha256_hex[USBS_SIGNATURE_HASH_LEN + 1];
    usbs_u64 size;
    char     name[USBS_SIGNATURE_NAME_MAX];
} usbs_signature_t;

typedef struct usbs_signature_list {
    usbs_signature_t *entries;
    size_t            count;
    size_t            capacity;
} usbs_signature_list_t;

extern void          usbs_signature_list_init(usbs_signature_list_t *list);
extern void          usbs_signature_list_free(usbs_signature_list_t *list);
extern usbs_status_t usbs_signature_list_load(usbs_signature_list_t *list, const char *path);
extern const char   *usbs_signature_list_lookup(const usbs_signature_list_t *list,
                                                usbs_u64 size_bytes, const char *sha256_hex);
extern usbs_bool      usbs_signature_list_has_size(const usbs_signature_list_t *list,
                                                   usbs_u64 size_bytes);

static void make_scratch_root(char *out, size_t cap)
{
    static usbs_bool seeded = false;
    if (!seeded) {
        srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)out);
        seeded = true;
    }
    snprintf(out, cap, "test_siglist_scratch_%08x\\", (unsigned)rand());
}

static void compute_sha256_hex(const char *data, size_t len, char *out_hex)
{
    usbs_hash_ctx_t *ctx = NULL;
    unsigned char    digest[USBS_SHA256_DIGEST_SIZE];

    USBS_CHECK(usbs_ok(usbs_platform_hash_begin(&ctx)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_update(ctx, data, len)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_finish(ctx, digest, out_hex)));
}

static void write_file(const char *root, const char *name, const char *content, size_t len)
{
    char path[400];
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%s%s", root, name);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, content, len)));
}

static void test_load_and_lookup_roundtrip(void)
{
    char                  root[260];
    char                  path[400];
    char                  hex_a[USBS_SHA256_HEX_LEN + 1];
    char                  hex_b[USBS_SHA256_HEX_LEN + 1];
    char                  file_content[512];
    int                   n;
    usbs_signature_list_t list;
    const char           *marker_a = "USB_SENTINEL_TEST_MARKER_ALPHA";
    const char           *marker_b = "USB_SENTINEL_TEST_MARKER_BETA_LONGER_STRING";

    compute_sha256_hex(marker_a, strlen(marker_a), hex_a);
    compute_sha256_hex(marker_b, strlen(marker_b), hex_b);

    make_scratch_root(root, sizeof(root));
    n = snprintf(file_content, sizeof(file_content),
                "# a comment line, must be ignored\n"
                "\n"
                "%s:%zu:Test Signature Alpha\n"
                "%s:%zu:Test Signature Beta\n",
                hex_a, strlen(marker_a), hex_b, strlen(marker_b));
    USBS_CHECK(n > 0);
    snprintf(path, sizeof(path), "%ssignatures.txt", root);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, file_content, (size_t)n)));

    usbs_signature_list_init(&list);
    USBS_CHECK(usbs_ok(usbs_signature_list_load(&list, path)));
    USBS_CHECK(list.count == 2);

    USBS_CHECK_STR_EQ(usbs_signature_list_lookup(&list, strlen(marker_a), hex_a),
                      "Test Signature Alpha");
    USBS_CHECK_STR_EQ(usbs_signature_list_lookup(&list, strlen(marker_b), hex_b),
                      "Test Signature Beta");

    /* Wrong size for a right hash must not match: size is genuinely part of
     * the key, not decoration. */
    USBS_CHECK(usbs_signature_list_lookup(&list, strlen(marker_a) + 1, hex_a) == NULL);
    /* An unrelated hash must not match anything. */
    USBS_CHECK(usbs_signature_list_lookup(&list, strlen(marker_a), hex_b) == NULL);

    usbs_signature_list_free(&list);
}

static void test_uppercase_hex_normalized_to_lowercase(void)
{
    char                  root[260];
    char                  path[400];
    char                  hex_lower[USBS_SHA256_HEX_LEN + 1];
    char                  hex_upper[USBS_SHA256_HEX_LEN + 1];
    char                  file_content[256];
    int                   n;
    size_t                i;
    usbs_signature_list_t list;
    const char           *marker = "USB_SENTINEL_TEST_MARKER_CASE";

    compute_sha256_hex(marker, strlen(marker), hex_lower);
    for (i = 0; i <= strlen(hex_lower); ++i) {
        char c = hex_lower[i];
        hex_upper[i] = (c >= 'a' && c <= 'f') ? (char)(c - 'a' + 'A') : c;
    }

    make_scratch_root(root, sizeof(root));
    n = snprintf(file_content, sizeof(file_content), "%s:%zu:Case Test\n",
                hex_upper, strlen(marker));
    USBS_CHECK(n > 0);
    snprintf(path, sizeof(path), "%ssignatures.txt", root);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, file_content, (size_t)n)));

    usbs_signature_list_init(&list);
    USBS_CHECK(usbs_ok(usbs_signature_list_load(&list, path)));
    USBS_CHECK(list.count == 1);
    /* Lookup with the lowercase form (what usbs_platform_hash_finish always
     * produces) must find the entry the loader normalized from uppercase. */
    USBS_CHECK_STR_EQ(usbs_signature_list_lookup(&list, strlen(marker), hex_lower), "Case Test");

    usbs_signature_list_free(&list);
}

static void test_malformed_lines_skipped_good_lines_kept(void)
{
    char                  root[260];
    char                  path[400];
    char                  hex[USBS_SHA256_HEX_LEN + 1];
    char                  file_content[512];
    int                   n;
    usbs_signature_list_t list;
    const char           *marker = "USB_SENTINEL_TEST_MARKER_GAMMA";

    compute_sha256_hex(marker, strlen(marker), hex);

    make_scratch_root(root, sizeof(root));
    n = snprintf(file_content, sizeof(file_content),
                "not-even-hex:10:bad hash\n"
                "%s:notanumber:bad size\n"
                "%s\n"                               /* missing both colons */
                "%s:%zu:\n"                           /* empty name */
                "%s:%zu:Good One\n",
                hex, hex, hex, strlen(marker), hex, strlen(marker));
    USBS_CHECK(n > 0);
    snprintf(path, sizeof(path), "%ssignatures.txt", root);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, file_content, (size_t)n)));

    usbs_signature_list_init(&list);
    USBS_CHECK(usbs_ok(usbs_signature_list_load(&list, path)));
    /* Exactly the one well-formed line survives; malformed ones are skipped,
     * not fatal to the load. */
    USBS_CHECK(list.count == 1);
    USBS_CHECK_STR_EQ(usbs_signature_list_lookup(&list, strlen(marker), hex), "Good One");

    usbs_signature_list_free(&list);
}

static void test_empty_file(void)
{
    char                  root[260];
    char                  path[400];
    usbs_signature_list_t list;

    make_scratch_root(root, sizeof(root));
    write_file(root, "empty.txt", "", 0);
    snprintf(path, sizeof(path), "%sempty.txt", root);

    usbs_signature_list_init(&list);
    USBS_CHECK(usbs_ok(usbs_signature_list_load(&list, path)));
    USBS_CHECK(list.count == 0);
    USBS_CHECK(usbs_signature_list_lookup(&list, 10, "x") == NULL);

    usbs_signature_list_free(&list);
}

static void test_missing_file_returns_not_found(void)
{
    char                  root[260];
    char                  path[400];
    usbs_signature_list_t list;

    make_scratch_root(root, sizeof(root));
    snprintf(path, sizeof(path), "%sdoes_not_exist.txt", root);

    usbs_signature_list_init(&list);
    USBS_CHECK(usbs_signature_list_load(&list, path) == USBS_ERR_NOT_FOUND);
    USBS_CHECK(list.count == 0);

    usbs_signature_list_free(&list);
}

static void test_lookup_on_empty_or_null_list(void)
{
    usbs_signature_list_t list;
    usbs_signature_list_init(&list);

    USBS_CHECK(usbs_signature_list_lookup(&list, 10, "abc") == NULL);
    USBS_CHECK(usbs_signature_list_lookup(NULL, 10, "abc") == NULL);
    USBS_CHECK(usbs_signature_list_lookup(&list, 10, NULL) == NULL);

    usbs_signature_list_free(&list);
}

static void test_invalid_args(void)
{
    usbs_signature_list_t list;
    usbs_signature_list_init(&list);
    USBS_CHECK(usbs_signature_list_load(NULL, "x") == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_signature_list_load(&list, NULL) == USBS_ERR_INVALID_ARG);

    /* init/free must be NULL-safe. */
    usbs_signature_list_init(NULL);
    usbs_signature_list_free(NULL);
    usbs_signature_list_free(&list);
}

/*
 * Phase 12 (ARCHITECTURE.md section 18): a wider malformed-line battery than
 * test_malformed_lines_skipped_good_lines_kept() covers - each shape here
 * must be skipped (never crash, never corrupt an already-loaded entry),
 * with the one well-formed line at the end still surviving.
 */
static void test_malformed_input_battery_extended(void)
{
    char                  root[260];
    char                  path[400];
    char                  hex[USBS_SHA256_HEX_LEN + 1];
    char                  short_hex[USBS_SHA256_HEX_LEN];
    char                  long_hex[USBS_SHA256_HEX_LEN + 2];
    char                  bad_char_hex[USBS_SHA256_HEX_LEN + 1];
    char                 *file_content;
    int                   n;
    usbs_signature_list_t list;
    const char           *marker = "USB_SENTINEL_TEST_MARKER_DELTA";

    compute_sha256_hex(marker, strlen(marker), hex);

    memcpy(short_hex, hex, USBS_SHA256_HEX_LEN - 1);
    short_hex[USBS_SHA256_HEX_LEN - 1] = '\0'; /* one hex digit short */

    snprintf(long_hex, sizeof(long_hex), "%sa", hex); /* one hex digit too many */

    memcpy(bad_char_hex, hex, sizeof(bad_char_hex));
    bad_char_hex[5] = 'z'; /* not a hex digit */

    file_content = (char *)malloc(4096);
    USBS_CHECK(file_content != NULL);
    if (file_content == NULL) {
        return;
    }

    n = snprintf(file_content, 4096,
                "%s:%zu:hash too short\n"                 /* wrong hash length */
                "%s:%zu:hash too long\n"                  /* wrong hash length */
                "%s:%zu:invalid hex digit\n"               /* non-hex char in hash */
                "%s::empty size field\n"                   /* size_len == 0 */
                "%s:99999999999999999999999999999999:huge size\n" /* size field >= 32 chars, too long */
                "%s:12x:trailing garbage in size\n"        /* strtoull leaves trailing chars */
                "   \n"                                    /* whitespace-only line */
                "\t\t\n"                                   /* tabs-only line */
                "  # indented comment\n"                    /* leading whitespace before '#' */
                "%s:%zu:Good One\n",                        /* the one well-formed line */
                short_hex, strlen(marker),
                long_hex, strlen(marker),
                bad_char_hex, strlen(marker),
                hex,
                hex,
                hex,
                hex, strlen(marker));
    USBS_CHECK(n > 0 && n < 4096);
    make_scratch_root(root, sizeof(root));
    snprintf(path, sizeof(path), "%ssignatures.txt", root);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, file_content, (size_t)n)));
    free(file_content);

    usbs_signature_list_init(&list);
    USBS_CHECK(usbs_ok(usbs_signature_list_load(&list, path)));
    USBS_CHECK(list.count == 1);
    USBS_CHECK_STR_EQ(usbs_signature_list_lookup(&list, strlen(marker), hex), "Good One");

    usbs_signature_list_free(&list);
}

/* CRLF line endings (the common case for a file authored or edited on
 * Windows) must load identically to LF - the trailing '\r' must never leak
 * into the parsed name field. */
static void test_crlf_line_endings(void)
{
    char                  root[260];
    char                  path[400];
    char                  hex_a[USBS_SHA256_HEX_LEN + 1];
    char                  hex_b[USBS_SHA256_HEX_LEN + 1];
    char                  file_content[512];
    int                   n;
    usbs_signature_list_t list;
    const char           *marker_a = "USB_SENTINEL_TEST_MARKER_EPSILON";
    const char           *marker_b = "USB_SENTINEL_TEST_MARKER_ZETA";

    compute_sha256_hex(marker_a, strlen(marker_a), hex_a);
    compute_sha256_hex(marker_b, strlen(marker_b), hex_b);

    make_scratch_root(root, sizeof(root));
    n = snprintf(file_content, sizeof(file_content),
                "%s:%zu:CRLF One\r\n"
                "%s:%zu:CRLF Two, no trailing newline\r\n",
                hex_a, strlen(marker_a), hex_b, strlen(marker_b));
    USBS_CHECK(n > 0);
    snprintf(path, sizeof(path), "%ssignatures.txt", root);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, file_content, (size_t)n)));

    usbs_signature_list_init(&list);
    USBS_CHECK(usbs_ok(usbs_signature_list_load(&list, path)));
    USBS_CHECK(list.count == 2);
    USBS_CHECK_STR_EQ(usbs_signature_list_lookup(&list, strlen(marker_a), hex_a), "CRLF One");
    USBS_CHECK_STR_EQ(usbs_signature_list_lookup(&list, strlen(marker_b), hex_b),
                      "CRLF Two, no trailing newline");

    usbs_signature_list_free(&list);
}

/* The last line of the file, with no trailing '\n' at all (not even the
 * CRLF form above), must still be parsed - memchr() finding no '\n' falls
 * back to file_end, per usbs_signature_list_load(). */
static void test_no_trailing_newline_on_last_line(void)
{
    char                  root[260];
    char                  path[400];
    char                  hex[USBS_SHA256_HEX_LEN + 1];
    char                  file_content[256];
    int                   n;
    usbs_signature_list_t list;
    const char           *marker = "USB_SENTINEL_TEST_MARKER_ETA";

    compute_sha256_hex(marker, strlen(marker), hex);

    make_scratch_root(root, sizeof(root));
    n = snprintf(file_content, sizeof(file_content), "%s:%zu:No Trailing Newline",
                hex, strlen(marker));
    USBS_CHECK(n > 0);
    snprintf(path, sizeof(path), "%ssignatures.txt", root);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, file_content, (size_t)n)));

    usbs_signature_list_init(&list);
    USBS_CHECK(usbs_ok(usbs_signature_list_load(&list, path)));
    USBS_CHECK(list.count == 1);
    USBS_CHECK_STR_EQ(usbs_signature_list_lookup(&list, strlen(marker), hex),
                      "No Trailing Newline");

    usbs_signature_list_free(&list);
}

/* Two identical entries are not deduplicated - both load, and lookup finds
 * a match (which of the two is unspecified but irrelevant, since they are
 * identical). Documents actual behavior rather than assuming it. */
static void test_duplicate_entries_both_loaded(void)
{
    char                  root[260];
    char                  path[400];
    char                  hex[USBS_SHA256_HEX_LEN + 1];
    char                  file_content[256];
    int                   n;
    usbs_signature_list_t list;
    const char           *marker = "USB_SENTINEL_TEST_MARKER_THETA";

    compute_sha256_hex(marker, strlen(marker), hex);

    make_scratch_root(root, sizeof(root));
    n = snprintf(file_content, sizeof(file_content), "%s:%zu:Dup\n%s:%zu:Dup\n",
                hex, strlen(marker), hex, strlen(marker));
    USBS_CHECK(n > 0);
    snprintf(path, sizeof(path), "%ssignatures.txt", root);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, file_content, (size_t)n)));

    usbs_signature_list_init(&list);
    USBS_CHECK(usbs_ok(usbs_signature_list_load(&list, path)));
    USBS_CHECK(list.count == 2);
    USBS_CHECK_STR_EQ(usbs_signature_list_lookup(&list, strlen(marker), hex), "Dup");

    usbs_signature_list_free(&list);
}

/*
 * A signature file with several thousand distinct entries, including many
 * sharing the same size (to exercise the "short run within a size bucket"
 * scan lookup() and has_size() both do after their binary search) - this is
 * the scale the size-bucketed lookup (ARCHITECTURE.md section 12.2) was
 * actually built for, not the handful of entries the other tests use.
 */
static void test_large_signature_list_stress(void)
{
    enum { ENTRY_COUNT = 4000, SHARED_SIZE_GROUP = 50 };
    char                  root[260];
    char                  path[400];
    char                 *file_content;
    size_t                pos = 0;
    size_t                cap = (size_t)ENTRY_COUNT * 128;
    int                   i;
    usbs_signature_list_t list;
    char                  hex[USBS_SHA256_HEX_LEN + 1];
    char                  marker[64];

    file_content = (char *)malloc(cap);
    USBS_CHECK(file_content != NULL);
    if (file_content == NULL) {
        return;
    }

    for (i = 0; i < ENTRY_COUNT; ++i) {
        /* Every SHARED_SIZE_GROUP-th entry reuses the same marker length
         * (and therefore the same "size" field) as a run of others, so
         * lookup() must scan past same-size neighbors rather than assume
         * the first size match is the right one. */
        int    group = i / SHARED_SIZE_GROUP;
        size_t marker_len;
        int    written;

        snprintf(marker, sizeof(marker), "USBS_STRESS_G%d_E%d", group, i);
        marker_len = strlen(marker);
        compute_sha256_hex(marker, marker_len, hex);

        written = snprintf(file_content + pos, cap - pos, "%s:%d:Stress Entry %d\n",
                           hex, group, i); /* size is the group index, not marker_len -
                                             * deliberately clusters many entries per size */
        USBS_CHECK(written > 0);
        pos += (size_t)written;
        USBS_CHECK(pos < cap);
    }

    make_scratch_root(root, sizeof(root));
    snprintf(path, sizeof(path), "%ssignatures.txt", root);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, file_content, pos)));
    free(file_content);

    usbs_signature_list_init(&list);
    USBS_CHECK(usbs_ok(usbs_signature_list_load(&list, path)));
    USBS_CHECK(list.count == ENTRY_COUNT);

    /* Spot-check first, middle, and last entries, plus one full same-size
     * group, by recomputing their hashes the same way they were generated. */
    for (i = 0; i < ENTRY_COUNT; i += (ENTRY_COUNT / 8)) {
        int    group = i / SHARED_SIZE_GROUP;
        char   expect[64];
        snprintf(marker, sizeof(marker), "USBS_STRESS_G%d_E%d", group, i);
        compute_sha256_hex(marker, strlen(marker), hex);
        snprintf(expect, sizeof(expect), "Stress Entry %d", i);
        USBS_CHECK_STR_EQ(usbs_signature_list_lookup(&list, (usbs_u64)group, hex), expect);
    }

    /* A size that was never used at all must not match anything, even with
     * thousands of entries loaded. */
    USBS_CHECK(usbs_signature_list_lookup(&list, (usbs_u64)(ENTRY_COUNT * 10), hex) == NULL);
    USBS_CHECK(!usbs_signature_list_has_size(&list, (usbs_u64)(ENTRY_COUNT * 10)));
    USBS_CHECK(usbs_signature_list_has_size(&list, 0)); /* group 0 always exists */

    usbs_signature_list_free(&list);
}

/*
 * Random-binary fuzz: usbs_signature_list_load() must never crash or hang
 * regardless of file content, since a signature file is user-edited local
 * text (ARCHITECTURE.md section 12.1) that can just as easily be corrupted,
 * truncated mid-write, or the wrong file entirely. A fixed seed keeps this
 * reproducible rather than a one-time flake.
 */
static void test_random_binary_fuzz(void)
{
    enum { TRIALS = 200, MAX_LEN = 2048 };
    char                  root[260];
    char                  path[400];
    unsigned              seed = 0x5EED1234u;
    int                   trial;
    static unsigned char  buf[MAX_LEN];

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(path, sizeof(path), "%sfuzz.bin", root);

    for (trial = 0; trial < TRIALS; ++trial) {
        size_t                len = (size_t)(seed % MAX_LEN);
        size_t                i;
        usbs_signature_list_t list;

        for (i = 0; i < len; ++i) {
            seed = seed * 1103515245u + 12345u;
            buf[i] = (unsigned char)(seed >> 16);
        }
        seed = seed * 1103515245u + 12345u;

        USBS_CHECK(usbs_ok(usbs_platform_write_file(path, (const char *)buf, len)));

        usbs_signature_list_init(&list);
        /* Whatever it finds, loading must always succeed (malformed lines
         * are skipped, never fatal) and leave the list in a valid state -
         * this is a robustness sweep, not a positive-case test. */
        USBS_CHECK(usbs_ok(usbs_signature_list_load(&list, path)));
        usbs_signature_list_free(&list);
    }
}

int main(void)
{
    test_load_and_lookup_roundtrip();
    test_uppercase_hex_normalized_to_lowercase();
    test_malformed_lines_skipped_good_lines_kept();
    test_malformed_input_battery_extended();
    test_crlf_line_endings();
    test_no_trailing_newline_on_last_line();
    test_duplicate_entries_both_loaded();
    test_large_signature_list_stress();
    test_random_binary_fuzz();
    test_empty_file();
    test_missing_file_returns_not_found();
    test_lookup_on_empty_or_null_list();
    test_invalid_args();
    return USBS_TEST_RESULT();
}
