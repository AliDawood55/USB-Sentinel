#include "usbsentinel/report.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "usbsentinel/json.h"
#include "usbsentinel/version.h"

/* ------------------------------------------------------------------------ *
 * JSON
 * ------------------------------------------------------------------------ */

static void write_device(usbs_json_writer_t *w, const usbs_device_t *device)
{
    char   identity[USBS_IDENTITY_MAX];
    usbs_u32 i;

    if (!usbs_ok(usbs_device_identity(device, identity, sizeof(identity)))) {
        identity[0] = '\0';
    }

    usbs_json_key(w, "device");
    usbs_json_begin_object(w);
    usbs_json_member_string(w, "identity", identity);
    /* Per ARCHITECTURE.md's volume-identity decision (device identity + the
     * volume GUID already carried in volume_path); computed inline since
     * this is the only caller. */
    {
        char volume_identity[USBS_IDENTITY_MAX + USBS_VOLUME_PATH_MAX];
        snprintf(volume_identity, sizeof(volume_identity), "%s/%s",
                 identity, device->volume_path);
        usbs_json_member_string(w, "volume_identity", volume_identity);
    }
    usbs_json_member_string(w, "bus_type", usbs_bus_type_string(device->bus_type));
    usbs_json_member_string(w, "vendor", device->vendor);
    usbs_json_member_string(w, "product", device->product);
    usbs_json_member_string(w, "volume_path", device->volume_path);

    usbs_json_key(w, "mount_points");
    usbs_json_begin_array(w);
    for (i = 0; i < device->mount_point_count; ++i) {
        usbs_json_string(w, device->mount_points[i]);
    }
    usbs_json_end_array(w);

    usbs_json_member_string(w, "filesystem", device->filesystem);
    usbs_json_member_bool(w, "media_present", device->media_present);
    usbs_json_member_uint(w, "capacity_bytes", device->capacity_bytes);
    usbs_json_member_uint(w, "free_bytes", device->free_bytes);
    usbs_json_end_object(w);
}

static void write_capabilities(usbs_json_writer_t *w, const usbs_capabilities_t *caps)
{
    usbs_json_key(w, "capabilities");
    usbs_json_begin_object(w);
    usbs_json_member_bool(w, "can_read_raw_volume", caps->can_read_raw_volume);
    usbs_json_member_bool(w, "can_read_physical_disk", caps->can_read_physical_disk);
    usbs_json_end_object(w);
}

static void write_checks(usbs_json_writer_t *w, const usbs_check_list_t *checks,
                         size_t *out_run, size_t *out_skipped, size_t *out_failed,
                         size_t *out_findings)
{
    size_t i;

    *out_run = *out_skipped = *out_failed = *out_findings = 0;

    usbs_json_key(w, "checks");
    usbs_json_begin_array(w);
    for (i = 0; i < checks->count; ++i) {
        const usbs_check_result_t *check = &checks->items[i];
        size_t                     j;

        usbs_json_begin_object(w);
        usbs_json_member_string(w, "id", check->id);
        usbs_json_member_string(w, "status", usbs_check_status_string(check->status));

        switch (check->status) {
        case USBS_CHECK_RAN:     ++(*out_run);     break;
        case USBS_CHECK_SKIPPED: ++(*out_skipped);
            usbs_json_member_string(w, "skip_reason", check->skip_reason);
            break;
        case USBS_CHECK_FAILED:  ++(*out_failed);
            usbs_json_member_string(w, "message", check->message);
            break;
        }
        if (check->status == USBS_CHECK_RAN && check->message[0] != '\0') {
            usbs_json_member_string(w, "message", check->message);
        }

        usbs_json_key(w, "findings");
        usbs_json_begin_array(w);
        for (j = 0; j < check->findings.count; ++j) {
            const usbs_finding_t *finding = &check->findings.items[j];
            ++(*out_findings);
            usbs_json_begin_object(w);
            usbs_json_member_string(w, "severity", usbs_severity_string(finding->severity));
            usbs_json_member_string(w, "path", finding->path);
            usbs_json_member_string(w, "message", finding->message);
            usbs_json_end_object(w);
        }
        usbs_json_end_array(w);

        usbs_json_end_object(w);
    }
    usbs_json_end_array(w);
}

usbs_status_t usbs_report_build_json(const usbs_scan_result_t *result,
                                     char                    **out_text,
                                     size_t                    *out_len)
{
    usbs_json_writer_t w;
    const char        *text;
    size_t             len;
    usbs_status_t      status;
    size_t             run, skipped, failed, findings;
    char              *copy;

    if (result == NULL || out_text == NULL || out_len == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    usbs_json_writer_init(&w);
    usbs_json_begin_object(&w);

    usbs_json_member_int(&w, "schema_version", USBS_REPORT_SCHEMA_VERSION);

    usbs_json_key(&w, "tool");
    usbs_json_begin_object(&w);
    usbs_json_member_string(&w, "name", USBS_PRODUCT_NAME);
    usbs_json_member_string(&w, "version", usbs_version_string());
    usbs_json_end_object(&w);

    usbs_json_key(&w, "scan");
    usbs_json_begin_object(&w);
    usbs_json_member_string(&w, "scan_id", result->scan_id);
    usbs_json_member_string(&w, "started_at", result->started_at);
    usbs_json_member_string(&w, "finished_at", result->finished_at);
    usbs_json_member_string(&w, "status", usbs_scan_status_string(result->status));
    usbs_json_end_object(&w);

    write_device(&w, &result->device);
    write_capabilities(&w, &result->capabilities);
    write_checks(&w, &result->checks, &run, &skipped, &failed, &findings);

    usbs_json_key(&w, "summary");
    usbs_json_begin_object(&w);
    usbs_json_member_uint(&w, "checks_run", (unsigned long long)run);
    usbs_json_member_uint(&w, "checks_skipped", (unsigned long long)skipped);
    usbs_json_member_uint(&w, "checks_failed", (unsigned long long)failed);
    usbs_json_member_uint(&w, "findings_count", (unsigned long long)findings);
    usbs_json_end_object(&w);

    usbs_json_end_object(&w); /* root */

    status = usbs_json_writer_finish(&w, &text, &len);
    if (!usbs_ok(status)) {
        usbs_json_writer_free(&w);
        return status;
    }

    copy = (char *)malloc(len + 1);
    if (copy == NULL) {
        usbs_json_writer_free(&w);
        return USBS_ERR_NO_MEMORY;
    }
    memcpy(copy, text, len + 1); /* text is NUL-terminated by the writer */
    usbs_json_writer_free(&w);

    *out_text = copy;
    *out_len  = len;
    return USBS_OK;
}

/* ------------------------------------------------------------------------ *
 * Text renderer - a formatter over the same structure, never a second
 * source of truth (ARCHITECTURE.md section 7.4).
 * ------------------------------------------------------------------------ */

static void format_size(usbs_u64 bytes, char *buf, size_t cap)
{
    const char *units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    double      value   = (double)bytes;
    size_t      unit    = 0;

    while (value >= 1024.0 && unit + 1 < USBS_ARRAY_LEN(units)) {
        value /= 1024.0;
        ++unit;
    }
    if (unit == 0) {
        snprintf(buf, cap, "%llu B", (unsigned long long)bytes);
    } else {
        snprintf(buf, cap, "%.1f %s", value, units[unit]);
    }
}

void usbs_report_render_text(const usbs_scan_result_t *result, FILE *stream)
{
    char   identity[USBS_IDENTITY_MAX];
    char   capacity[32];
    size_t i;
    size_t skipped_count = 0;
    size_t failed_count  = 0;

    if (result == NULL || stream == NULL) {
        return;
    }

    if (!usbs_ok(usbs_device_identity(&result->device, identity, sizeof(identity)))) {
        snprintf(identity, sizeof(identity), "(unknown)");
    }

    fprintf(stream, "USB Sentinel scan report\n");
    fprintf(stream, "  scan id      %s\n", result->scan_id);
    fprintf(stream, "  started      %s\n", result->started_at);
    fprintf(stream, "  finished     %s\n", result->finished_at);
    fprintf(stream, "  status       %s\n", usbs_scan_status_string(result->status));
    fprintf(stream, "\n");
    fprintf(stream, "  device       %s\n", identity);
    fprintf(stream, "  bus          %s\n", usbs_bus_type_string(result->device.bus_type));
    if (result->device.vendor[0] != '\0' || result->device.product[0] != '\0') {
        fprintf(stream, "  hardware     %s %s\n", result->device.vendor, result->device.product);
    }
    format_size(result->device.capacity_bytes, capacity, sizeof(capacity));
    fprintf(stream, "  capacity     %s\n", capacity);
    fprintf(stream, "\n");
    fprintf(stream, "  raw volume   %s\n",
            result->capabilities.can_read_raw_volume ? "available"
                                                       : "unavailable (requires elevation)");
    fprintf(stream, "  raw disk     %s\n",
            result->capabilities.can_read_physical_disk ? "available"
                                                          : "unavailable (requires elevation)");
    fprintf(stream, "\n");

    fprintf(stream, "  checks:\n");
    for (i = 0; i < result->checks.count; ++i) {
        const usbs_check_result_t *check = &result->checks.items[i];
        size_t                     j;

        fprintf(stream, "    [%s] %s\n", usbs_check_status_string(check->status), check->id);
        if (check->status == USBS_CHECK_SKIPPED) {
            ++skipped_count;
            fprintf(stream, "        reason: %s\n", check->skip_reason);
        } else if (check->status == USBS_CHECK_FAILED) {
            ++failed_count;
            fprintf(stream, "        error: %s\n", check->message);
        } else if (check->message[0] != '\0') {
            fprintf(stream, "        %s\n", check->message);
        }
        for (j = 0; j < check->findings.count; ++j) {
            const usbs_finding_t *finding = &check->findings.items[j];
            const char           *severity = usbs_severity_string(finding->severity);
            if (finding->path[0] != '\0') {
                fprintf(stream, "        finding [%s]: %s: %s\n",
                        severity, finding->path, finding->message);
            } else {
                fprintf(stream, "        finding [%s]: %s\n", severity, finding->message);
            }
        }
    }

    /* Skipped/failed checks are always summarized, never left to be inferred
     * from the absence of findings - a silent capability gap is worse than
     * no report (ARCHITECTURE.md section 7.3). */
    fprintf(stream, "\n");
    if (skipped_count > 0 || failed_count > 0) {
        fprintf(stream, "  %zu check(s) skipped, %zu check(s) failed - see above.\n",
                skipped_count, failed_count);
    } else {
        fprintf(stream, "  All checks ran.\n");
    }
    fprintf(stream, "\n  Scanning is read-only: no file was opened for writing.\n");
}

/* ------------------------------------------------------------------------ *
 * CSV - RFC 4180 quoting, plus a formula-injection mitigation for fields
 * that could originate from attacker-controlled content (a filename, or
 * LNK-derived text) and would otherwise be interpreted as a formula if the
 * CSV is later opened in a spreadsheet application.
 * ------------------------------------------------------------------------ */

typedef struct csv_buf {
    char  *data;
    size_t len;
    size_t cap;
} csv_buf_t;

static usbs_status_t csv_ensure(csv_buf_t *b, size_t extra)
{
    size_t needed;
    size_t new_cap;
    char  *grown;

    needed = b->len + extra + 1; /* +1 keeps the buffer always NUL-terminatable */
    if (needed <= b->cap) {
        return USBS_OK;
    }

    new_cap = (b->cap == 0) ? 512 : b->cap;
    while (new_cap < needed) {
        if (new_cap > SIZE_MAX / 2) {
            return USBS_ERR_NO_MEMORY;
        }
        new_cap *= 2;
    }

    grown = (char *)realloc(b->data, new_cap);
    if (grown == NULL) {
        return USBS_ERR_NO_MEMORY;
    }
    b->data = grown;
    b->cap  = new_cap;
    return USBS_OK;
}

static usbs_status_t csv_append(csv_buf_t *b, const char *text, size_t n)
{
    usbs_status_t status = csv_ensure(b, n);
    if (!usbs_ok(status)) {
        return status;
    }
    memcpy(b->data + b->len, text, n);
    b->len += n;
    b->data[b->len] = '\0';
    return USBS_OK;
}

static usbs_status_t csv_append_str(csv_buf_t *b, const char *text)
{
    return csv_append(b, text, strlen(text));
}

/* Writes one field, comma-separated from whatever preceded it on this row
 * (the caller is responsible for the comma itself, via csv_field's `first`
 * handling below) - quoted per RFC 4180 whenever it contains a comma,
 * quote, or newline (embedded quotes doubled), and additionally prefixed
 * with a leading single quote - always inside quotes when this applies -
 * when the field begins with '=', '+', '-', or '@', the classic
 * spreadsheet formula-injection trigger. This content can come from an
 * attacker-controlled filename or LNK-derived string; nothing USB Sentinel
 * itself generates would ever need this. */
static usbs_status_t csv_write_field(csv_buf_t *b, const char *value)
{
    size_t        len;
    usbs_bool     needs_quote = false;
    usbs_bool     needs_formula_prefix;
    size_t        i;
    usbs_status_t status;

    if (value == NULL) {
        value = "";
    }
    len = strlen(value);
    needs_formula_prefix = (len > 0) &&
        (value[0] == '=' || value[0] == '+' || value[0] == '-' || value[0] == '@');

    for (i = 0; i < len; ++i) {
        if (value[i] == ',' || value[i] == '"' || value[i] == '\n' || value[i] == '\r') {
            needs_quote = true;
            break;
        }
    }

    if (!needs_quote && !needs_formula_prefix) {
        return csv_append(b, value, len);
    }

    status = csv_append(b, "\"", 1);
    if (!usbs_ok(status)) {
        return status;
    }
    if (needs_formula_prefix) {
        status = csv_append(b, "'", 1);
        if (!usbs_ok(status)) {
            return status;
        }
    }
    for (i = 0; i < len; ++i) {
        if (value[i] == '"') {
            status = csv_append(b, "\"\"", 2);
        } else {
            status = csv_append(b, value + i, 1);
        }
        if (!usbs_ok(status)) {
            return status;
        }
    }
    return csv_append(b, "\"", 1);
}

/* One data row: scan_id,device_identity,check_id,check_status,skip_reason,
 * check_message,severity,path,message */
static usbs_status_t csv_write_row(csv_buf_t *b, const char *scan_id, const char *device_identity,
                                   const char *check_id, const char *check_status,
                                   const char *skip_reason, const char *check_message,
                                   const char *severity, const char *path, const char *message)
{
    const char *fields[9];
    size_t      i;
    usbs_status_t status;

    fields[0] = scan_id;
    fields[1] = device_identity;
    fields[2] = check_id;
    fields[3] = check_status;
    fields[4] = skip_reason;
    fields[5] = check_message;
    fields[6] = severity;
    fields[7] = path;
    fields[8] = message;

    for (i = 0; i < USBS_ARRAY_LEN(fields); ++i) {
        if (i > 0) {
            status = csv_append(b, ",", 1);
            if (!usbs_ok(status)) {
                return status;
            }
        }
        status = csv_write_field(b, fields[i]);
        if (!usbs_ok(status)) {
            return status;
        }
    }
    return csv_append(b, "\r\n", 2);
}

usbs_status_t usbs_report_build_csv(const usbs_scan_result_t *result,
                                    char                    **out_text,
                                    size_t                    *out_len)
{
    csv_buf_t     b;
    char          identity[USBS_IDENTITY_MAX];
    size_t        i;
    usbs_status_t status;
    char         *copy;

    if (result == NULL || out_text == NULL || out_len == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    memset(&b, 0, sizeof(b));

    if (!usbs_ok(usbs_device_identity(&result->device, identity, sizeof(identity)))) {
        identity[0] = '\0';
    }

    status = csv_append_str(&b,
        "scan_id,device_identity,check_id,check_status,skip_reason,"
        "check_message,severity,path,message\r\n");
    if (!usbs_ok(status)) {
        free(b.data);
        return status;
    }

    for (i = 0; i < result->checks.count; ++i) {
        const usbs_check_result_t *check      = &result->checks.items[i];
        const char                *status_str = usbs_check_status_string(check->status);
        const char *skip_reason = (check->status == USBS_CHECK_SKIPPED) ? check->skip_reason : "";

        if (check->findings.count == 0) {
            /* A check with nothing to report is still one row, never simply
             * absent (ARCHITECTURE.md section 7.3 - the same discipline
             * JSON already has, now also holding for CSV). */
            status = csv_write_row(&b, result->scan_id, identity, check->id, status_str,
                                   skip_reason, check->message, "", "", "");
            if (!usbs_ok(status)) {
                free(b.data);
                return status;
            }
            continue;
        }

        {
            size_t j;
            for (j = 0; j < check->findings.count; ++j) {
                const usbs_finding_t *finding = &check->findings.items[j];
                status = csv_write_row(&b, result->scan_id, identity, check->id, status_str,
                                       skip_reason, check->message,
                                       usbs_severity_string(finding->severity),
                                       finding->path, finding->message);
                if (!usbs_ok(status)) {
                    free(b.data);
                    return status;
                }
            }
        }
    }

    if (b.data == NULL) {
        /* No checks at all: still a valid CSV, header row only. Should not
         * happen in practice (usbs_scanner_scan always produces at least
         * file_traversal), but csv_append_str already guaranteed b.data is
         * non-NULL once the header was written, so this path is dead in
         * practice and kept only as a defensive guard. */
        return USBS_ERR_INTERNAL;
    }

    copy = (char *)malloc(b.len + 1);
    if (copy == NULL) {
        free(b.data);
        return USBS_ERR_NO_MEMORY;
    }
    memcpy(copy, b.data, b.len + 1);
    free(b.data);

    *out_text = copy;
    *out_len  = b.len;
    return USBS_OK;
}
