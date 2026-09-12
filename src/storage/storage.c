#include "usbsentinel/storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "usbsentinel/env.h"
#include "usbsentinel/json.h"
#include "usbsentinel/log.h"
#include "usbsentinel/platform.h"

#define USBS_INDEX_SCHEMA_VERSION 1

/* --- path helpers --- */

static usbs_status_t path_join(char *out, size_t cap, const char *a, const char *b)
{
    int written = snprintf(out, cap, "%s\\%s", a, b);
    if (written < 0 || (size_t)written >= cap) {
        return USBS_ERR_NO_MEMORY;
    }
    return USBS_OK;
}

static usbs_status_t scans_root(const usbs_store_t *store, char *out, size_t cap)
{
    return path_join(out, cap, store->root, "scans");
}

static usbs_status_t device_dir(const usbs_store_t *store, const char *safe_id,
                                char *out, size_t cap)
{
    char root[USBS_STORE_PATH_MAX];
    usbs_status_t status = scans_root(store, root, sizeof(root));
    if (!usbs_ok(status)) {
        return status;
    }
    return path_join(out, cap, root, safe_id);
}

static usbs_status_t index_path(const usbs_store_t *store, char *out, size_t cap)
{
    return path_join(out, cap, store->root, "index.json");
}

usbs_status_t usbs_store_safe_id(const char *device_identity, char *out, size_t cap)
{
    const unsigned char *p;
    size_t                len = 0;

    if (device_identity == NULL || out == NULL || cap == 0) {
        return USBS_ERR_INVALID_ARG;
    }

    for (p = (const unsigned char *)device_identity; *p != '\0'; ++p) {
        usbs_bool safe = (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
                         (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == '_';
        size_t    need = safe ? 1 : 3; /* "_XX" for an escaped byte */

        if (len + need >= cap) {
            return USBS_ERR_NO_MEMORY;
        }
        if (safe) {
            out[len++] = (char)*p;
        } else {
            snprintf(out + len, 4, "_%02X", (unsigned)*p);
            len += 3;
        }
    }
    if (len == 0) {
        return USBS_ERR_INVALID_ARG;
    }
    out[len] = '\0';
    return USBS_OK;
}

/* "2026-09-11T14:02:03Z" -> "20260911T140203Z" (exactly 16 chars). Filenames
 * use this compact form so a report's timestamp prefix has a fixed, known
 * width and can be split from the scan-id suffix by position rather than by
 * searching for a delimiter character that a GUID-shaped scan-id could also
 * contain. */
static usbs_status_t compact_timestamp(const char *iso, char *out, size_t cap)
{
    size_t len = 0;
    const char *p;

    if (iso == NULL || out == NULL || cap < 17) {
        return USBS_ERR_INVALID_ARG;
    }
    for (p = iso; *p != '\0'; ++p) {
        if (*p == '-' || *p == ':') {
            continue;
        }
        if (len + 1 >= cap) {
            return USBS_ERR_INVALID_ARG;
        }
        out[len++] = *p;
    }
    out[len] = '\0';
    if (len != 16) {
        return USBS_ERR_INVALID_ARG; /* not a well-formed "...T...Z" UTC stamp */
    }
    return USBS_OK;
}

static usbs_status_t expand_timestamp(const char *compact, char *out, size_t cap)
{
    /* "20260911T140203Z" -> "2026-09-11T14:02:03Z" */
    if (compact == NULL || strlen(compact) != 16 || out == NULL || cap < 21) {
        return USBS_ERR_INVALID_ARG;
    }
    snprintf(out, cap, "%.4s-%.2s-%.2sT%.2s:%.2s:%.2sZ",
             compact, compact + 4, compact + 6,
             compact + 9, compact + 11, compact + 13);
    return USBS_OK;
}

static usbs_bool ends_with(const char *s, const char *suffix)
{
    size_t s_len      = strlen(s);
    size_t suffix_len = strlen(suffix);
    if (suffix_len > s_len) {
        return false;
    }
    return strcmp(s + (s_len - suffix_len), suffix) == 0;
}

/* --- open --- */

usbs_status_t usbs_store_open_at(const char *root, usbs_store_t *out_store)
{
    usbs_status_t status;
    char          scans[USBS_STORE_PATH_MAX];

    if (root == NULL || out_store == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (snprintf(out_store->root, sizeof(out_store->root), "%s", root) < 0) {
        return USBS_ERR_INVALID_ARG;
    }

    status = usbs_platform_make_dirs(out_store->root);
    if (!usbs_ok(status)) {
        return status;
    }

    status = scans_root(out_store, scans, sizeof(scans));
    if (!usbs_ok(status)) {
        return status;
    }
    return usbs_platform_make_dirs(scans);
}

usbs_status_t usbs_store_open(usbs_store_t *out_store)
{
    char          local_app_data[USBS_STORE_PATH_MAX];
    char          root[USBS_STORE_PATH_MAX];
    usbs_status_t status;

    if (out_store == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    status = usbs_getenv("LOCALAPPDATA", local_app_data, sizeof(local_app_data));
    if (!usbs_ok(status)) {
        USBS_LOG_E("%%LOCALAPPDATA%% is not set; cannot locate the report store");
        return USBS_ERR_NOT_FOUND;
    }

    status = (snprintf(root, sizeof(root), "%s\\USBSentinel", local_app_data) < 0)
                 ? USBS_ERR_INTERNAL
                 : USBS_OK;
    if (!usbs_ok(status)) {
        return status;
    }
    return usbs_store_open_at(root, out_store);
}

/* --- last-scan lookup (directory-derived, never trusts index.json) --- */

usbs_status_t usbs_store_last_scan(const usbs_store_t     *store,
                                   const char              *device_identity,
                                   usbs_store_last_scan_t *out_info)
{
    char             safe_id[USBS_STORE_PATH_MAX];
    char             dir[USBS_STORE_PATH_MAX];
    usbs_status_t    status;
    usbs_dir_iter_t *iter;
    char             best[USBS_NAME_MAX];
    usbs_bool        have_best = false;

    if (store == NULL || device_identity == NULL || out_info == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    memset(out_info, 0, sizeof(*out_info));

    status = usbs_store_safe_id(device_identity, safe_id, sizeof(safe_id));
    if (!usbs_ok(status)) {
        return status;
    }
    status = device_dir(store, safe_id, dir, sizeof(dir));
    if (!usbs_ok(status)) {
        return status;
    }

    status = usbs_platform_dir_open(dir, &iter);
    if (status == USBS_ERR_NOT_FOUND) {
        return USBS_OK; /* device never scanned before: found stays false */
    }
    if (!usbs_ok(status)) {
        return status;
    }

    for (;;) {
        usbs_dir_entry_t entry;
        status = usbs_platform_dir_next(iter, &entry);
        if (status == USBS_ERR_NOT_FOUND) {
            break; /* end of listing */
        }
        if (!usbs_ok(status)) {
            usbs_platform_dir_close(iter);
            return status;
        }
        if (entry.is_directory || !ends_with(entry.name, ".json")) {
            continue;
        }

        ++out_info->report_count;
        /* Filenames are "<16-char timestamp>-<scan-id>.json"; lexical order
         * matches chronological order, so the greatest name is the newest. */
        if (!have_best || strcmp(entry.name, best) > 0) {
            snprintf(best, sizeof(best), "%s", entry.name);
            have_best = true;
        }
    }
    usbs_platform_dir_close(iter);

    if (have_best) {
        char timestamp_part[17];
        size_t name_len = strlen(best);

        /* "<16><->< scan-id >.json"; minimum well-formed length is
         * 16 (timestamp) + 1 ('-') + 0 (scan-id may be empty) + 5 (".json"). */
        if (name_len >= 22 && best[16] == '-' && ends_with(best, ".json")) {
            size_t id_len = name_len - 17 - 5; /* minus timestamp, '-', ".json" */

            memcpy(timestamp_part, best, 16);
            timestamp_part[16] = '\0';
            expand_timestamp(timestamp_part, out_info->scanned_at,
                            sizeof(out_info->scanned_at));

            if (id_len < sizeof(out_info->scan_id)) {
                memcpy(out_info->scan_id, best + 17, id_len);
                out_info->scan_id[id_len] = '\0';
            }
        }
        out_info->found = true;
    }

    return USBS_OK;
}

/* --- whole-file read, for the best-effort index.json refresh --- */

static usbs_status_t read_whole_file(const char *path, char **out_buf, size_t *out_len)
{
    usbs_file_t  *file;
    usbs_status_t status;
    char         *buf = NULL;
    size_t        len = 0;
    size_t        cap = 0;

    status = usbs_platform_file_open_read(path, &file);
    if (!usbs_ok(status)) {
        return status;
    }

    for (;;) {
        size_t read = 0;
        if (len + 4096 > cap) {
            size_t new_cap = cap == 0 ? 4096 : cap * 2;
            char  *grown    = (char *)realloc(buf, new_cap);
            if (grown == NULL) {
                free(buf);
                usbs_platform_file_close(file);
                return USBS_ERR_NO_MEMORY;
            }
            buf = grown;
            cap = new_cap;
        }

        status = usbs_platform_file_read(file, buf + len, cap - len, &read);
        if (!usbs_ok(status)) {
            free(buf);
            usbs_platform_file_close(file);
            return status;
        }
        if (read == 0) {
            break;
        }
        len += read;
    }

    usbs_platform_file_close(file);
    *out_buf = buf;
    *out_len = len;
    return USBS_OK;
}

/* Rewrites index.json to reflect `device_identity`'s current directory-derived
 * state, preserving every other device's entry found in the existing (or
 * freshly rebuilt) index. Best-effort: failures are logged, never propagated,
 * since index.json is a cache - ARCHITECTURE.md's detection-data-format
 * decision. */
static void refresh_index(const usbs_store_t *store, const char *device_identity)
{
    char                safe_id[USBS_STORE_PATH_MAX];
    char                path[USBS_STORE_PATH_MAX];
    char                temp_path[USBS_STORE_PATH_MAX];
    char               *existing_text = NULL;
    size_t              existing_len  = 0;
    usbs_json_value_t  *existing_root = NULL;
    const usbs_json_value_t *existing_devices = NULL;
    usbs_json_writer_t  writer;
    usbs_store_last_scan_t last;
    size_t              i;
    const char         *text;
    size_t              text_len;
    usbs_status_t       status;

    if (!usbs_ok(usbs_store_safe_id(device_identity, safe_id, sizeof(safe_id)))) {
        return;
    }
    if (!usbs_ok(index_path(store, path, sizeof(path)))) {
        return;
    }
    if (!usbs_ok(usbs_store_last_scan(store, device_identity, &last))) {
        return;
    }

    /* Best-effort read of the existing index; a missing or corrupt file just
     * means we start from an empty document - this is the self-healing path
     * that satisfies "index.json as rebuildable cache". */
    if (usbs_ok(read_whole_file(path, &existing_text, &existing_len))) {
        if (!usbs_ok(usbs_json_parse(existing_text, existing_len, &existing_root))) {
            USBS_LOG_W("index.json is corrupt; rebuilding it");
            existing_root = NULL;
        }
    }
    if (existing_root != NULL) {
        existing_devices = usbs_json_object_get(existing_root, "devices");
    }

    usbs_json_writer_init(&writer);
    usbs_json_begin_object(&writer);
    usbs_json_member_int(&writer, "schema_version", USBS_INDEX_SCHEMA_VERSION);
    usbs_json_key(&writer, "devices");
    usbs_json_begin_object(&writer);

    /* Carry forward every other device's entry unchanged. */
    if (existing_devices != NULL) {
        size_t count = usbs_json_object_count(existing_devices);
        for (i = 0; i < count; ++i) {
            const char *key = usbs_json_object_key_at(existing_devices, i);
            const usbs_json_value_t *val = usbs_json_object_value_at(existing_devices, i);
            const usbs_json_value_t *v_id, *v_at, *v_count;
            long long                count_num;

            if (key == NULL || strcmp(key, safe_id) == 0) {
                continue; /* this device is rewritten fresh below */
            }
            v_id    = usbs_json_object_get(val, "last_scan_id");
            v_at    = usbs_json_object_get(val, "last_scan_at");
            v_count = usbs_json_object_get(val, "report_count");
            if (v_id == NULL || v_at == NULL || !usbs_json_as_int(v_count, &count_num)) {
                continue; /* malformed entry; drop it rather than propagate it */
            }

            usbs_json_key(&writer, key);
            usbs_json_begin_object(&writer);
            usbs_json_member_string(&writer, "last_scan_id", usbs_json_as_string(v_id));
            usbs_json_member_string(&writer, "last_scan_at", usbs_json_as_string(v_at));
            usbs_json_member_int(&writer, "report_count", count_num);
            usbs_json_end_object(&writer);
        }
    }

    if (last.found) {
        usbs_json_key(&writer, safe_id);
        usbs_json_begin_object(&writer);
        usbs_json_member_string(&writer, "last_scan_id", last.scan_id);
        usbs_json_member_string(&writer, "last_scan_at", last.scanned_at);
        usbs_json_member_int(&writer, "report_count", (long long)last.report_count);
        usbs_json_end_object(&writer);
    }

    usbs_json_end_object(&writer); /* devices */
    usbs_json_end_object(&writer); /* root */

    usbs_json_free(existing_root);
    free(existing_text);

    status = usbs_json_writer_finish(&writer, &text, &text_len);
    if (!usbs_ok(status)) {
        USBS_LOG_W("failed to build index.json: %s", usbs_status_string(status));
        usbs_json_writer_free(&writer);
        return;
    }

    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
    status = usbs_platform_write_file(temp_path, text, text_len);
    if (usbs_ok(status)) {
        status = usbs_platform_replace_file(path, temp_path);
    }
    if (!usbs_ok(status)) {
        USBS_LOG_W("failed to write index.json: %s", usbs_status_string(status));
        usbs_platform_delete_file(temp_path);
    }

    usbs_json_writer_free(&writer);
}

/* --- write report --- */

/*
 * Shared by usbs_store_write_report() and usbs_store_write_report_csv():
 * everything about an atomic, named write into a device's report directory
 * except the index refresh, which only the JSON write triggers (both files
 * for one scan share a scan_id/timestamp, so refreshing once is enough -
 * see usbs_store_write_report_csv()'s own comment).
 */
static usbs_status_t write_report_file(const usbs_store_t *store,
                                       const char          *device_identity,
                                       const char          *scan_id,
                                       const char          *timestamp_utc,
                                       const char          *extension,
                                       const char          *content,
                                       size_t               content_len,
                                       char                *out_path,
                                       size_t               out_path_cap)
{
    char          safe_id[USBS_STORE_PATH_MAX];
    char          dir[USBS_STORE_PATH_MAX];
    char          compact[17];
    char          filename[300];
    char          final_path[USBS_STORE_PATH_MAX];
    char          temp_path[USBS_STORE_PATH_MAX];
    usbs_status_t status;

    if (store == NULL || device_identity == NULL || scan_id == NULL ||
        timestamp_utc == NULL || content == NULL || extension == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (strchr(scan_id, '\\') != NULL || strchr(scan_id, '/') != NULL) {
        return USBS_ERR_INVALID_ARG; /* scan_id becomes part of a filename */
    }

    status = usbs_store_safe_id(device_identity, safe_id, sizeof(safe_id));
    if (!usbs_ok(status)) {
        return status;
    }
    status = device_dir(store, safe_id, dir, sizeof(dir));
    if (!usbs_ok(status)) {
        return status;
    }
    status = usbs_platform_make_dirs(dir);
    if (!usbs_ok(status)) {
        return status;
    }

    status = compact_timestamp(timestamp_utc, compact, sizeof(compact));
    if (!usbs_ok(status)) {
        return status;
    }

    if (snprintf(filename, sizeof(filename), "%s-%s.%s", compact, scan_id, extension) < 0) {
        return USBS_ERR_INTERNAL;
    }
    status = path_join(final_path, sizeof(final_path), dir, filename);
    if (!usbs_ok(status)) {
        return status;
    }
    if (snprintf(temp_path, sizeof(temp_path), "%s.tmp", final_path) < 0) {
        return USBS_ERR_INTERNAL;
    }

    status = usbs_platform_write_file(temp_path, content, content_len);
    if (!usbs_ok(status)) {
        usbs_platform_delete_file(temp_path);
        return status;
    }

    status = usbs_platform_replace_file(final_path, temp_path);
    if (!usbs_ok(status)) {
        usbs_platform_delete_file(temp_path);
        return status;
    }

    if (out_path != NULL && out_path_cap > 0) {
        snprintf(out_path, out_path_cap, "%s", final_path);
    }
    return USBS_OK;
}

usbs_status_t usbs_store_write_report(const usbs_store_t *store,
                                      const char          *device_identity,
                                      const char          *scan_id,
                                      const char          *timestamp_utc,
                                      const char          *json_text,
                                      size_t               json_len,
                                      char                *out_path,
                                      size_t               out_path_cap)
{
    usbs_status_t status = write_report_file(store, device_identity, scan_id, timestamp_utc,
                                             "json", json_text, json_len,
                                             out_path, out_path_cap);
    if (!usbs_ok(status)) {
        return status;
    }
    refresh_index(store, device_identity); /* best-effort; see its own comment */
    return USBS_OK;
}

/*
 * Writes `csv_text` as a companion file for the same report - same
 * directory, same "<timestamp>-<scan_id>" stem, ".csv" extension instead of
 * ".json". Same atomicity guarantee as usbs_store_write_report(). Does not
 * refresh index.json itself: call this for a (device_identity, scan_id,
 * timestamp_utc) already passed to usbs_store_write_report() (in either
 * order), whose own call already covers the refresh for this scan - a
 * second refresh here would be redundant, not incorrect, so callers are not
 * required to order the two calls a particular way.
 */
usbs_status_t usbs_store_write_report_csv(const usbs_store_t *store,
                                          const char          *device_identity,
                                          const char          *scan_id,
                                          const char          *timestamp_utc,
                                          const char          *csv_text,
                                          size_t               csv_len,
                                          char                *out_path,
                                          size_t               out_path_cap)
{
    return write_report_file(store, device_identity, scan_id, timestamp_utc,
                             "csv", csv_text, csv_len, out_path, out_path_cap);
}
