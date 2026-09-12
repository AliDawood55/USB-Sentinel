#include <stdlib.h>
#include <string.h>

#include "test_util.h"
#include "usbsentinel/json.h"

static void test_writer_basic(void)
{
    usbs_json_writer_t w;
    const char        *text = NULL;
    size_t             len  = 0;

    usbs_json_writer_init(&w);
    usbs_json_begin_object(&w);
    usbs_json_member_int(&w, "schema_version", 1);
    usbs_json_member_string(&w, "name", "USB Sentinel");
    usbs_json_member_bool(&w, "elevated", false);
    usbs_json_key(&w, "checks");
    usbs_json_begin_array(&w);
    usbs_json_begin_object(&w);
    usbs_json_member_string(&w, "id", "autorun_inspection");
    usbs_json_member_string(&w, "status", "ran");
    usbs_json_end_object(&w);
    usbs_json_begin_object(&w);
    usbs_json_member_string(&w, "id", "boot_sector_analysis");
    usbs_json_member_string(&w, "status", "skipped");
    usbs_json_end_object(&w);
    usbs_json_end_array(&w);
    usbs_json_end_object(&w);

    USBS_CHECK(usbs_ok(usbs_json_writer_finish(&w, &text, &len)));
    USBS_CHECK(text != NULL);
    if (text != NULL) {
        USBS_CHECK(len == strlen(text));
        USBS_CHECK(strstr(text, "\"schema_version\":1") != NULL);
        USBS_CHECK(strstr(text, "\"name\":\"USB Sentinel\"") != NULL);
        USBS_CHECK(strstr(text, "\"elevated\":false") != NULL);
        USBS_CHECK(strstr(text, "autorun_inspection") != NULL);
    }

    usbs_json_writer_free(&w);
}

static void test_writer_escaping(void)
{
    usbs_json_writer_t w;
    const char        *text = NULL;
    size_t             len  = 0;

    usbs_json_writer_init(&w);
    usbs_json_begin_object(&w);
    usbs_json_member_string(&w, "path", "C:\\Users\\a\"b\"\\file\nname.txt");
    usbs_json_end_object(&w);

    USBS_CHECK(usbs_ok(usbs_json_writer_finish(&w, &text, &len)));
    USBS_CHECK(text != NULL);
    if (text != NULL) {
        USBS_CHECK(strstr(text, "\\\\Users\\\\") != NULL);
        USBS_CHECK(strstr(text, "\\\"b\\\"") != NULL);
        USBS_CHECK(strstr(text, "\\n") != NULL);

        /* The escaped output must itself parse back to the original string. */
        {
            usbs_json_value_t *root = NULL;
            const usbs_json_value_t *path;
            USBS_CHECK(usbs_ok(usbs_json_parse(text, len, &root)));
            path = usbs_json_object_get(root, "path");
            USBS_CHECK_STR_EQ(usbs_json_as_string(path),
                              "C:\\Users\\a\"b\"\\file\nname.txt");
            usbs_json_free(root);
        }
    }

    usbs_json_writer_free(&w);
}

/* A container left open must be reported, not silently closed. */
static void test_writer_unclosed_is_error(void)
{
    usbs_json_writer_t w;
    const char        *text;
    size_t             len;

    usbs_json_writer_init(&w);
    usbs_json_begin_object(&w);
    usbs_json_member_int(&w, "a", 1);
    /* no end_object */

    USBS_CHECK(usbs_json_writer_finish(&w, &text, &len) != USBS_OK);
    usbs_json_writer_free(&w);
}

static void test_reader_roundtrip(void)
{
    const char *doc =
        "{ \"schema_version\": 1, \"devices\": { \"usb:0781-5583\": "
        "{ \"last_scan_id\": \"abc\", \"report_count\": 3 } }, "
        "\"tags\": [\"a\", \"b\", 42, true, null] }";

    usbs_json_value_t       *root = NULL;
    const usbs_json_value_t *devices;
    const usbs_json_value_t *device;
    const usbs_json_value_t *tags;
    long long                n;

    USBS_CHECK(usbs_ok(usbs_json_parse(doc, strlen(doc), &root)));
    USBS_CHECK(usbs_json_type(root) == USBS_JSON_OBJECT);

    USBS_CHECK(usbs_json_as_int(usbs_json_object_get(root, "schema_version"), &n));
    USBS_CHECK(n == 1);

    devices = usbs_json_object_get(root, "devices");
    USBS_CHECK(usbs_json_type(devices) == USBS_JSON_OBJECT);
    USBS_CHECK(usbs_json_object_count(devices) == 1);
    USBS_CHECK_STR_EQ(usbs_json_object_key_at(devices, 0), "usb:0781-5583");

    device = usbs_json_object_value_at(devices, 0);
    USBS_CHECK_STR_EQ(usbs_json_as_string(usbs_json_object_get(device, "last_scan_id")),
                      "abc");
    USBS_CHECK(usbs_json_as_int(usbs_json_object_get(device, "report_count"), &n));
    USBS_CHECK(n == 3);

    tags = usbs_json_object_get(root, "tags");
    USBS_CHECK(usbs_json_array_count(tags) == 5);
    USBS_CHECK_STR_EQ(usbs_json_as_string(usbs_json_array_at(tags, 0)), "a");
    USBS_CHECK(usbs_json_type(usbs_json_array_at(tags, 3)) == USBS_JSON_BOOL);
    USBS_CHECK(usbs_json_type(usbs_json_array_at(tags, 4)) == USBS_JSON_NULL);

    usbs_json_free(root);
}

/* Corrupt/malformed input must fail cleanly, never crash or read garbage. */
static void test_reader_rejects_malformed(void)
{
    const char *bad_inputs[] = {
        "",
        "{",
        "{\"a\":}",
        "{\"a\" 1}",
        "[1, 2,]",
        "{\"a\":1} trailing",
        "tru",
        "{\"a\": \"unterminated}",
    };
    size_t i;

    for (i = 0; i < USBS_ARRAY_LEN(bad_inputs); ++i) {
        usbs_json_value_t *root = NULL;
        usbs_status_t status = usbs_json_parse(bad_inputs[i], strlen(bad_inputs[i]), &root);
        USBS_CHECK(!usbs_ok(status));
        USBS_CHECK(root == NULL);
        if (root != NULL) {
            usbs_json_free(root); /* would only run if the check above failed */
        }
    }
}

static void test_reader_depth_limit(void)
{
    /* 40 nested arrays exceeds USBS_JSON_PARSE_MAX_DEPTH (32); must fail
     * cleanly rather than overflow the parser's call stack. */
    char   doc[128];
    size_t i;
    size_t pos = 0;

    for (i = 0; i < 40; ++i) {
        doc[pos++] = '[';
    }
    for (i = 0; i < 40; ++i) {
        doc[pos++] = ']';
    }
    doc[pos] = '\0';

    {
        usbs_json_value_t *root = NULL;
        USBS_CHECK(!usbs_ok(usbs_json_parse(doc, pos, &root)));
    }
}

/* Phase 12 (ARCHITECTURE.md section 18): the depth limit must apply
 * uniformly regardless of which container type is doing the nesting - an
 * attacker (or a corrupt index.json) is not obliged to use arrays. */
static void test_reader_depth_limit_applies_to_nested_objects(void)
{
    char   doc[512];
    size_t i;
    size_t pos = 0;

    for (i = 0; i < 40; ++i) {
        doc[pos++] = '{';
        doc[pos++] = '"';
        doc[pos++] = 'a';
        doc[pos++] = '"';
        doc[pos++] = ':';
    }
    doc[pos++] = '1';
    for (i = 0; i < 40; ++i) {
        doc[pos++] = '}';
    }
    doc[pos] = '\0';

    {
        usbs_json_value_t *root = NULL;
        USBS_CHECK(!usbs_ok(usbs_json_parse(doc, pos, &root)));
    }

    /* Just inside the limit must still succeed - this is a boundary check,
     * not just "large nesting fails". The depth check in parse_value() runs
     * on every call, including the innermost leaf value's own call - not
     * only on the calls that recurse into another container - so 31 nested
     * objects (each holding a real value, unlike the empty-array case
     * above) is the deepest that leaves the leaf number's own check
     * (at depth 31) still under USBS_JSON_PARSE_MAX_DEPTH (32). Verified
     * against the actual parser rather than assumed: an off-by-one here
     * was caught by running this test, not by reasoning about the code. */
    pos = 0;
    for (i = 0; i < 31; ++i) {
        doc[pos++] = '{';
        doc[pos++] = '"';
        doc[pos++] = 'a';
        doc[pos++] = '"';
        doc[pos++] = ':';
    }
    doc[pos++] = '1';
    for (i = 0; i < 31; ++i) {
        doc[pos++] = '}';
    }
    doc[pos] = '\0';

    {
        usbs_json_value_t *root = NULL;
        USBS_CHECK(usbs_ok(usbs_json_parse(doc, pos, &root)));
        usbs_json_free(root);
    }
}

/* Extended malformed-input battery (Phase 12): every shape here must be
 * rejected cleanly (non-OK status, *out_value untouched) rather than crash
 * or silently accept nonsense - the same discipline test_reader_rejects_
 * malformed() already applies, grown with edge cases that battery didn't
 * cover: broken \u escapes, bad number shapes, mismatched brackets, and
 * stray control/UTF garbage. */
static void test_reader_rejects_malformed_extended(void)
{
    const char *bad_inputs[] = {
        "{\"a\": \"\\u12\"}",       /* truncated \u escape (2 hex digits, needs 4) */
        "{\"a\": \"\\u12zz\"}",     /* \u escape with non-hex digits */
        "{\"a\": \"\\q\"}",         /* unknown escape letter */
        "{\"a\": \"unterminated",   /* string never closed, no closing brace either */
        "{\"a\": -}",               /* lone minus, no digits */
        "{\"a\": --1}",             /* doubled sign */
        "{\"a\": 1.2.3}",           /* two decimal points */
        "{\"a\": 1e}",              /* exponent with no digits */
        "[1, 2}",                  /* array closed with the wrong bracket */
        "{\"a\": 1]",               /* object closed with the wrong bracket */
        "{,}",                     /* comma with no members at all */
        "[,]",                     /* comma with no elements at all */
        "nul",                     /* truncated literal */
        "{\"a\":1}{\"b\":2}",       /* two documents concatenated */
    };
    size_t i;

    for (i = 0; i < USBS_ARRAY_LEN(bad_inputs); ++i) {
        usbs_json_value_t *root = NULL;
        usbs_status_t status = usbs_json_parse(bad_inputs[i], strlen(bad_inputs[i]), &root);
        USBS_CHECK(!usbs_ok(status));
        USBS_CHECK(root == NULL);
        if (root != NULL) {
            usbs_json_free(root); /* would only run if the check above failed */
        }
    }

    /* Raw binary garbage, not text at all - kept separate from the
     * strlen()-based table above since it contains an embedded NUL. */
    {
        static const char  raw[] = { '\xff', '\xfe', '\x00', '\x01' };
        usbs_json_value_t *root  = NULL;
        usbs_status_t      status = usbs_json_parse(raw, sizeof(raw), &root);
        USBS_CHECK(!usbs_ok(status));
        USBS_CHECK(root == NULL);
        if (root != NULL) {
            usbs_json_free(root);
        }
    }
}

/*
 * Forces the writer's \uXXXX-decode string buffer through many growth
 * cycles - the exact realloc() call sites Phase 12's /analyze pass found
 * silently leaking the original buffer on allocation failure
 * (ARCHITECTURE.md section 18: buf = realloc(buf, ...) overwriting buf
 * before the NULL check). Not a leak reproduction (that needs realloc to
 * actually fail, which this test cannot force portably) - this instead
 * proves the *fixed* code still decodes correctly across many growths of
 * both the <0x80 and >=0x80 branches, since a mechanical fix to error
 * handling could easily have broken the success path it left untouched.
 */
static void test_parser_many_unicode_escapes_stress(void)
{
    /* 3000 repeats of an ASCII \u escape (grows via the code < 0x80 branch)
     * followed by 3000 repeats of a 2-byte UTF-8 \u escape (the >= 0x80
     * branch) - both realloc call sites this phase touched. */
    enum { REPEATS = 3000 };
    char  *doc;
    size_t pos = 0;
    size_t i;
    usbs_json_value_t       *root = NULL;
    const usbs_json_value_t *val;
    const char              *decoded;

    doc = (char *)malloc(4 + REPEATS * 6 * 2 + 8);
    USBS_CHECK(doc != NULL);
    if (doc == NULL) {
        return;
    }

    doc[pos++] = '"';
    for (i = 0; i < REPEATS; ++i) {
        memcpy(doc + pos, "\\u0041", 6); /* 'A' */
        pos += 6;
    }
    for (i = 0; i < REPEATS; ++i) {
        memcpy(doc + pos, "\\u00e9", 6); /* U+00E9, 2-byte UTF-8 */
        pos += 6;
    }
    doc[pos++] = '"';

    USBS_CHECK(usbs_ok(usbs_json_parse(doc, pos, &root)));
    val = root;
    decoded = usbs_json_as_string(val);
    USBS_CHECK(decoded != NULL);
    if (decoded != NULL) {
        size_t len = strlen(decoded);
        /* REPEATS ASCII bytes + REPEATS * 2 UTF-8 bytes. */
        USBS_CHECK(len == REPEATS + REPEATS * 2);
        for (i = 0; i < REPEATS; ++i) {
            USBS_CHECK(decoded[i] == 'A');
        }
        for (i = 0; i < (size_t)REPEATS; ++i) {
            unsigned char c0 = (unsigned char)decoded[REPEATS + i * 2];
            unsigned char c1 = (unsigned char)decoded[REPEATS + i * 2 + 1];
            USBS_CHECK(c0 == 0xC3 && c1 == 0xA9); /* U+00E9 in UTF-8 */
        }
    }

    usbs_json_free(root);
    free(doc);
}

/* A large, wide (not deep) document: many array elements and object
 * members round-tripped through the writer, then the reader. Complements
 * the depth-limit tests above, which stress nesting rather than breadth. */
static void test_writer_reader_large_document_roundtrip(void)
{
    enum { N = 5000 };
    usbs_json_writer_t  w;
    const char         *text = NULL;
    size_t              len  = 0;
    int                 i;
    usbs_json_value_t       *root = NULL;
    const usbs_json_value_t *arr;

    usbs_json_writer_init(&w);
    usbs_json_begin_array(&w);
    for (i = 0; i < N; ++i) {
        usbs_json_begin_object(&w);
        usbs_json_member_int(&w, "index", i);
        usbs_json_member_string(&w, "label", "finding");
        usbs_json_end_object(&w);
    }
    usbs_json_end_array(&w);

    USBS_CHECK(usbs_ok(usbs_json_writer_finish(&w, &text, &len)));
    USBS_CHECK(text != NULL);

    if (text != NULL) {
        USBS_CHECK(usbs_ok(usbs_json_parse(text, len, &root)));
        arr = root;
        USBS_CHECK(usbs_json_array_count(arr) == N);
        if (usbs_json_array_count(arr) == N) {
            long long n;
            USBS_CHECK(usbs_json_as_int(
                usbs_json_object_get(usbs_json_array_at(arr, 0), "index"), &n));
            USBS_CHECK(n == 0);
            USBS_CHECK(usbs_json_as_int(
                usbs_json_object_get(usbs_json_array_at(arr, N - 1), "index"), &n));
            USBS_CHECK(n == N - 1);
        }
        usbs_json_free(root);
    }

    usbs_json_writer_free(&w);
}

/*
 * Random-binary fuzz: usbs_json_parse() must never crash, hang, or leak
 * regardless of input, since a corrupt index.json (disk error, another
 * process, a hand-edited file) is exactly the kind of input this parser
 * has to survive - ARCHITECTURE.md section 9.1 already treats a corrupted
 * index.json as an expected, non-fatal case. A fixed seed keeps this
 * reproducible: a failure here should be debuggable, not a one-time flake.
 */
static void test_reader_random_binary_fuzz(void)
{
    static unsigned char buf[256];
    unsigned              seed = 0xC0FFEEu;
    int                   trial;

    for (trial = 0; trial < 500; ++trial) {
        size_t len = (size_t)(seed % sizeof(buf));
        size_t i;
        usbs_json_value_t *root = NULL;

        for (i = 0; i < len; ++i) {
            seed = seed * 1103515245u + 12345u;
            buf[i] = (unsigned char)(seed >> 16);
        }
        seed = seed * 1103515245u + 12345u;

        /* Whatever it decides, it must decide cleanly: either a non-OK
         * status with *out_value untouched, or success with a tree that
         * frees without incident. Almost every trial here is malformed by
         * construction (random bytes vs. a strict grammar), so this is
         * really a robustness sweep, not a positive-case test. */
        if (usbs_ok(usbs_json_parse((const char *)buf, len, &root))) {
            USBS_CHECK(root != NULL);
            usbs_json_free(root);
        } else {
            USBS_CHECK(root == NULL);
        }
    }
}

int main(void)
{
    test_writer_basic();
    test_writer_escaping();
    test_writer_unclosed_is_error();
    test_reader_roundtrip();
    test_reader_rejects_malformed();
    test_reader_rejects_malformed_extended();
    test_reader_depth_limit();
    test_reader_depth_limit_applies_to_nested_objects();
    test_parser_many_unicode_escapes_stress();
    test_writer_reader_large_document_roundtrip();
    test_reader_random_binary_fuzz();
    return USBS_TEST_RESULT();
}
