/*
 * Storage tests run against a real, uniquely-named scratch directory (no
 * hardware, no mocking - filesystem operations are generic OS operations,
 * not USB-specific). Each run gets a fresh directory name so leftovers from
 * a previous run cannot affect correctness; the small JSON artifacts are
 * left under build/ (already git-ignored) rather than adding a
 * recursive-delete API to platform.h purely for test cleanup.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "test_util.h"
#include "usbsentinel/json.h"
#include "usbsentinel/platform.h"
#include "usbsentinel/storage.h"

static void make_scratch_root(char *out, size_t cap)
{
    static usbs_bool seeded = false;
    if (!seeded) {
        srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)out);
        seeded = true;
    }
    snprintf(out, cap, "test_storage_scratch_%08x", (unsigned)rand());
}

static usbs_status_t read_whole(const char *path, char *buf, size_t cap, size_t *out_len)
{
    usbs_file_t  *file;
    usbs_status_t status = usbs_platform_file_open_read(path, &file);
    size_t        total  = 0;

    if (!usbs_ok(status)) {
        return status;
    }
    for (;;) {
        size_t read = 0;
        status = usbs_platform_file_read(file, buf + total, cap - total - 1, &read);
        if (!usbs_ok(status) || read == 0) {
            break;
        }
        total += read;
    }
    usbs_platform_file_close(file);
    buf[total] = '\0';
    *out_len = total;
    return status;
}

static void test_open_creates_layout(void)
{
    char         root[260];
    usbs_store_t store;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_store_open_at(root, &store)));
    USBS_CHECK_STR_EQ(store.root, root);

    /* Opening twice must be idempotent, not an error. */
    USBS_CHECK(usbs_ok(usbs_store_open_at(root, &store)));
}

static void test_open_rejects_null(void)
{
    usbs_store_t store;
    USBS_CHECK(usbs_store_open_at(NULL, &store) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_store_open_at("some_root", NULL) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_store_open(NULL) == USBS_ERR_INVALID_ARG);
}

static void test_safe_id_encoding(void)
{
    char buf[128];

    USBS_CHECK(usbs_ok(usbs_store_safe_id("usb:0781-5583:AA11", buf, sizeof(buf))));
    /* ':' (0x3A) must be escaped; '-' passes through unescaped. */
    USBS_CHECK_STR_EQ(buf, "usb_3A0781-5583_3AAA11");

    /* Every output byte must be alnum, '.', '-', or '_'. */
    {
        const char *p;
        for (p = buf; *p != '\0'; ++p) {
            usbs_bool ok = (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
                          (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == '_';
            USBS_CHECK(ok);
        }
    }

    USBS_CHECK(usbs_store_safe_id(NULL, buf, sizeof(buf)) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_store_safe_id("x", NULL, sizeof(buf)) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_store_safe_id("x", buf, 0) == USBS_ERR_INVALID_ARG);

    /* A buffer too small to hold the encoding is reported, not truncated. */
    {
        char tiny[3];
        USBS_CHECK(usbs_store_safe_id("usb:AA", tiny, sizeof(tiny)) == USBS_ERR_NO_MEMORY);
    }
}

static void test_write_and_last_scan(void)
{
    char                    root[260];
    usbs_store_t            store;
    char                    saved_path[512];
    usbs_status_t           status;
    usbs_store_last_scan_t  info;
    char                    file_contents[256];
    size_t                  file_len;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_store_open_at(root, &store)));

    status = usbs_store_write_report(&store, "usb:1111-2222:SERIAL1", "abc123",
                                     "2026-09-11T14:02:03Z", "{\"schema_version\":1}", 20,
                                     saved_path, sizeof(saved_path));
    USBS_CHECK(usbs_ok(status));
    USBS_CHECK(saved_path[0] != '\0');
    USBS_CHECK(strstr(saved_path, "20260911T140203Z-abc123.json") != NULL);

    USBS_CHECK(usbs_ok(read_whole(saved_path, file_contents, sizeof(file_contents), &file_len)));
    USBS_CHECK_STR_EQ(file_contents, "{\"schema_version\":1}");

    USBS_CHECK(usbs_ok(usbs_store_last_scan(&store, "usb:1111-2222:SERIAL1", &info)));
    USBS_CHECK(info.found);
    USBS_CHECK(info.report_count == 1);
    USBS_CHECK_STR_EQ(info.scan_id, "abc123");
    USBS_CHECK_STR_EQ(info.scanned_at, "2026-09-11T14:02:03Z");
}

/* Phase 7: the CSV companion writes into the same directory, same stem,
 * ".csv" instead of ".json" - and must not be counted as a second scan by
 * usbs_store_last_scan() (which only counts ".json" files). */
static void test_write_csv_companion(void)
{
    char                    root[260];
    usbs_store_t            store;
    char                    json_path[512];
    char                    csv_path[512];
    usbs_status_t           status;
    usbs_store_last_scan_t  info;
    char                    file_contents[256];
    size_t                  file_len;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_store_open_at(root, &store)));

    status = usbs_store_write_report(&store, "usb:CSV0-0000:S1", "csv123",
                                     "2026-09-11T15:00:00Z", "{\"schema_version\":1}", 20,
                                     json_path, sizeof(json_path));
    USBS_CHECK(usbs_ok(status));

    status = usbs_store_write_report_csv(&store, "usb:CSV0-0000:S1", "csv123",
                                         "2026-09-11T15:00:00Z", "a,b,c\r\n1,2,3\r\n", 14,
                                         csv_path, sizeof(csv_path));
    USBS_CHECK(usbs_ok(status));
    USBS_CHECK(csv_path[0] != '\0');
    USBS_CHECK(strstr(csv_path, "20260911T150000Z-csv123.csv") != NULL);

    /* Same directory and stem as the JSON file, only the extension differs. */
    {
        size_t json_len = strlen(json_path);
        size_t csv_len  = strlen(csv_path);
        USBS_CHECK(json_len > 5 && csv_len > 4);
        if (json_len > 5 && csv_len > 4) {
            USBS_CHECK(strncmp(json_path, csv_path, json_len - 5) == 0); /* strip ".json"/".csv" */
        }
    }

    USBS_CHECK(usbs_ok(read_whole(csv_path, file_contents, sizeof(file_contents), &file_len)));
    USBS_CHECK_STR_EQ(file_contents, "a,b,c\r\n1,2,3\r\n");

    /* Exactly one scan on record, not two, despite two files. */
    USBS_CHECK(usbs_ok(usbs_store_last_scan(&store, "usb:CSV0-0000:S1", &info)));
    USBS_CHECK(info.found);
    USBS_CHECK(info.report_count == 1);
}

static void test_write_csv_invalid_args(void)
{
    char         root[260];
    usbs_store_t store;
    char         path[512];

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_store_open_at(root, &store)));

    USBS_CHECK(usbs_store_write_report_csv(NULL, "id", "s", "2026-09-11T09:00:00Z", "x", 1,
                                           path, sizeof(path)) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_store_write_report_csv(&store, NULL, "s", "2026-09-11T09:00:00Z", "x", 1,
                                           path, sizeof(path)) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_store_write_report_csv(&store, "id", "a/b", "2026-09-11T09:00:00Z", "x", 1,
                                           path, sizeof(path)) == USBS_ERR_INVALID_ARG);
}

static void test_last_scan_unknown_device(void)
{
    char                    root[260];
    usbs_store_t            store;
    usbs_store_last_scan_t  info;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_store_open_at(root, &store)));

    USBS_CHECK(usbs_ok(usbs_store_last_scan(&store, "usb:never-scanned:X", &info)));
    USBS_CHECK(!info.found);
    USBS_CHECK(info.report_count == 0);
}

static void test_last_scan_picks_newest(void)
{
    char                    root[260];
    usbs_store_t            store;
    char                    path[512];
    usbs_store_last_scan_t  info;
    const char             *identity = "usb:AAAA-BBBB:S1";

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_store_open_at(root, &store)));

    /* Written out of chronological order: newest ("2026-09-11T09:00:00Z")
     * first, then an older one, then a middle one. The lookup must still
     * report the chronologically newest, not the most recently written. */
    USBS_CHECK(usbs_ok(usbs_store_write_report(&store, identity, "mid",
                       "2026-09-11T09:00:00Z", "{}", 2, path, sizeof(path))));
    USBS_CHECK(usbs_ok(usbs_store_write_report(&store, identity, "oldest",
                       "2026-09-10T09:00:00Z", "{}", 2, path, sizeof(path))));
    USBS_CHECK(usbs_ok(usbs_store_write_report(&store, identity, "newest",
                       "2026-09-12T09:00:00Z", "{}", 2, path, sizeof(path))));

    USBS_CHECK(usbs_ok(usbs_store_last_scan(&store, identity, &info)));
    USBS_CHECK(info.report_count == 3);
    USBS_CHECK_STR_EQ(info.scan_id, "newest");
    USBS_CHECK_STR_EQ(info.scanned_at, "2026-09-12T09:00:00Z");
}

static void test_no_temp_file_left_behind(void)
{
    char                    root[260];
    usbs_store_t            store;
    char                    path[512];
    char                    safe_id[260];
    char                    dir[512];
    usbs_dir_iter_t        *iter;
    usbs_bool               saw_tmp = false;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_store_open_at(root, &store)));
    USBS_CHECK(usbs_ok(usbs_store_write_report(&store, "usb:CCCC-DDDD:S2", "scanid",
                       "2026-09-11T09:00:00Z", "{}", 2, path, sizeof(path))));

    USBS_CHECK(usbs_ok(usbs_store_safe_id("usb:CCCC-DDDD:S2", safe_id, sizeof(safe_id))));
    snprintf(dir, sizeof(dir), "%s\\scans\\%s", root, safe_id);

    USBS_CHECK(usbs_ok(usbs_platform_dir_open(dir, &iter)));
    for (;;) {
        usbs_dir_entry_t entry;
        if (usbs_platform_dir_next(iter, &entry) != USBS_OK) {
            break;
        }
        if (strstr(entry.name, ".tmp") != NULL) {
            saw_tmp = true;
        }
    }
    usbs_platform_dir_close(iter);
    USBS_CHECK(!saw_tmp);
}

/* A corrupt index.json must neither break last_scan (directory-derived,
 * never trusts the index) nor break the next write (self-healing rewrite). */
static void test_corrupt_index_self_heals(void)
{
    char                    root[260];
    usbs_store_t            store;
    char                    index_path[300];
    char                    path[512];
    usbs_store_last_scan_t  info;
    char                    index_contents[512];
    size_t                  index_len;
    usbs_json_value_t      *parsed = NULL;
    long long               schema_version = 0;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_store_open_at(root, &store)));
    USBS_CHECK(usbs_ok(usbs_store_write_report(&store, "usb:EEEE-FFFF:S3", "first",
                       "2026-09-11T09:00:00Z", "{}", 2, path, sizeof(path))));

    snprintf(index_path, sizeof(index_path), "%s\\index.json", root);
    USBS_CHECK(usbs_ok(usbs_platform_write_file(index_path, "{ this is not json", 18)));

    /* last_scan must still be correct despite the corruption. */
    USBS_CHECK(usbs_ok(usbs_store_last_scan(&store, "usb:EEEE-FFFF:S3", &info)));
    USBS_CHECK(info.found);
    USBS_CHECK_STR_EQ(info.scan_id, "first");

    /* The next write must still succeed and rebuild a valid index.json. */
    USBS_CHECK(usbs_ok(usbs_store_write_report(&store, "usb:EEEE-FFFF:S3", "second",
                       "2026-09-11T10:00:00Z", "{}", 2, path, sizeof(path))));

    USBS_CHECK(usbs_ok(read_whole(index_path, index_contents, sizeof(index_contents), &index_len)));
    USBS_CHECK(usbs_ok(usbs_json_parse(index_contents, index_len, &parsed)));
    USBS_CHECK(usbs_json_as_int(usbs_json_object_get(parsed, "schema_version"), &schema_version));
    USBS_CHECK(schema_version == 1);
    usbs_json_free(parsed);
}

static void test_write_report_invalid_args(void)
{
    char         root[260];
    usbs_store_t store;
    char         path[512];

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_store_open_at(root, &store)));

    USBS_CHECK(usbs_store_write_report(NULL, "id", "s", "2026-09-11T09:00:00Z", "{}", 2,
                                       path, sizeof(path)) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_store_write_report(&store, NULL, "s", "2026-09-11T09:00:00Z", "{}", 2,
                                       path, sizeof(path)) == USBS_ERR_INVALID_ARG);
    /* A scan-id containing a path separator must be rejected, not smuggled
     * into a filename. */
    USBS_CHECK(usbs_store_write_report(&store, "id", "a/b", "2026-09-11T09:00:00Z", "{}", 2,
                                       path, sizeof(path)) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_store_write_report(&store, "id", "a\\b", "2026-09-11T09:00:00Z", "{}", 2,
                                       path, sizeof(path)) == USBS_ERR_INVALID_ARG);
    /* A malformed timestamp (not 16 chars once punctuation is stripped)
     * must be rejected too. */
    USBS_CHECK(usbs_store_write_report(&store, "id", "s", "not-a-timestamp", "{}", 2,
                                       path, sizeof(path)) == USBS_ERR_INVALID_ARG);
}

int main(void)
{
    test_open_creates_layout();
    test_open_rejects_null();
    test_safe_id_encoding();
    test_write_and_last_scan();
    test_write_csv_companion();
    test_write_csv_invalid_args();
    test_last_scan_unknown_device();
    test_last_scan_picks_newest();
    test_no_temp_file_left_behind();
    test_corrupt_index_self_heals();
    test_write_report_invalid_args();
    return USBS_TEST_RESULT();
}
