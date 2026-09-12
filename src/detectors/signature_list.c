#include "signature_list.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "usbsentinel/log.h"
#include "usbsentinel/platform.h"

/* A real signature file is user-supplied, not attacker-controlled USB
 * content, so this is a generous ceiling rather than a tight DoS bound -
 * still bounded, so a mistakenly-huge file cannot make a load unbounded. */
#define USBS_SIGNATURE_FILE_MAX_READ (64u * 1024u * 1024u)

/* Bounds how many "malformed line" warnings a badly-formed file can produce;
 * the total count is still logged once at the end regardless. */
#define USBS_SIGNATURE_MAX_WARNINGS 10

void usbs_signature_list_init(usbs_signature_list_t *list)
{
    if (list == NULL) {
        return;
    }
    list->entries  = NULL;
    list->count    = 0;
    list->capacity = 0;
}

void usbs_signature_list_free(usbs_signature_list_t *list)
{
    if (list == NULL) {
        return;
    }
    free(list->entries);
    list->entries  = NULL;
    list->count    = 0;
    list->capacity = 0;
}

static usbs_status_t push_entry(usbs_signature_list_t *list, const usbs_signature_t *entry)
{
    if (list->count == list->capacity) {
        size_t            next = (list->capacity == 0) ? 64 : list->capacity * 2;
        usbs_signature_t *grown;

        if (next > SIZE_MAX / sizeof(usbs_signature_t)) {
            return USBS_ERR_NO_MEMORY;
        }
        grown = (usbs_signature_t *)realloc(list->entries, next * sizeof(usbs_signature_t));
        if (grown == NULL) {
            return USBS_ERR_NO_MEMORY;
        }
        list->entries  = grown;
        list->capacity = next;
    }
    list->entries[list->count++] = *entry;
    return USBS_OK;
}

static int compare_by_size(const void *a, const void *b)
{
    const usbs_signature_t *sa = (const usbs_signature_t *)a;
    const usbs_signature_t *sb = (const usbs_signature_t *)b;
    if (sa->size < sb->size) return -1;
    if (sa->size > sb->size) return 1;
    return 0;
}

/* --- bounded whole-file read --- */

static usbs_status_t read_whole_file_capped(const char *path, char **out_buf, size_t *out_len)
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

        if (len >= USBS_SIGNATURE_FILE_MAX_READ) {
            USBS_LOG_W("signature file %s exceeds %u bytes; truncating read",
                      path, (unsigned)USBS_SIGNATURE_FILE_MAX_READ);
            break;
        }
        if (len + 65536 > cap) {
            size_t new_cap = (cap == 0) ? 65536 : cap * 2;
            char  *grown;
            if (new_cap > USBS_SIGNATURE_FILE_MAX_READ + 65536) {
                new_cap = USBS_SIGNATURE_FILE_MAX_READ + 65536;
            }
            grown = (char *)realloc(buf, new_cap);
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

/* --- line parsing --- */

typedef enum line_result {
    LINE_SKIP_QUIET, /* blank or '#' comment */
    LINE_MALFORMED,
    LINE_OK
} line_result_t;

static line_result_t parse_line(const char *line, size_t len, usbs_signature_t *out)
{
    const char *p   = line;
    const char *end = line + len;
    const char *hash_start;
    const char *hash_end;
    const char *size_start;
    const char *size_end;
    const char *name_start;
    const char *name_end;
    size_t      hash_len;
    size_t      size_len;
    char        size_buf[32];
    char       *endptr;
    unsigned long long size_val;
    size_t      i;

    while (p < end && (*p == ' ' || *p == '\t')) {
        ++p;
    }
    if (p >= end || *p == '#' || *p == '\r') {
        return LINE_SKIP_QUIET;
    }

    hash_start = p;
    hash_end   = (const char *)memchr(p, ':', (size_t)(end - p));
    if (hash_end == NULL) {
        return LINE_MALFORMED;
    }
    hash_len = (size_t)(hash_end - hash_start);
    if (hash_len != USBS_SIGNATURE_HASH_LEN) {
        return LINE_MALFORMED;
    }

    size_start = hash_end + 1;
    size_end   = (const char *)memchr(size_start, ':', (size_t)(end - size_start));
    if (size_end == NULL) {
        return LINE_MALFORMED;
    }
    size_len = (size_t)(size_end - size_start);
    if (size_len == 0 || size_len >= sizeof(size_buf)) {
        return LINE_MALFORMED;
    }
    memcpy(size_buf, size_start, size_len);
    size_buf[size_len] = '\0';

    name_start = size_end + 1;
    name_end   = end;
    while (name_end > name_start &&
          (name_end[-1] == '\r' || name_end[-1] == '\n' ||
           name_end[-1] == ' '  || name_end[-1] == '\t')) {
        --name_end;
    }
    if (name_end <= name_start) {
        return LINE_MALFORMED; /* empty name */
    }

    /* Validate and normalize the hash to lowercase in one pass. */
    for (i = 0; i < hash_len; ++i) {
        char c = hash_start[i];
        if (c >= 'A' && c <= 'F') {
            c = (char)(c - 'A' + 'a');
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return LINE_MALFORMED;
        }
        out->sha256_hex[i] = c;
    }
    out->sha256_hex[hash_len] = '\0';

    size_val = strtoull(size_buf, &endptr, 10);
    if (endptr != size_buf + size_len) {
        return LINE_MALFORMED; /* trailing garbage in the size field */
    }
    out->size = (usbs_u64)size_val;

    {
        size_t name_len = (size_t)(name_end - name_start);
        if (name_len >= sizeof(out->name)) {
            name_len = sizeof(out->name) - 1;
        }
        memcpy(out->name, name_start, name_len);
        out->name[name_len] = '\0';
    }

    return LINE_OK;
}

usbs_status_t usbs_signature_list_load(usbs_signature_list_t *list, const char *path)
{
    char         *buf = NULL;
    size_t        len = 0;
    usbs_status_t status;
    const char   *line_start;
    const char   *file_end;
    size_t        line_no  = 0;
    size_t        skipped  = 0;

    if (list == NULL || path == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    status = read_whole_file_capped(path, &buf, &len);
    if (!usbs_ok(status)) {
        return status; /* USBS_ERR_NOT_FOUND propagates as-is: "no file", not an error */
    }

    line_start = buf;
    file_end   = buf + len;

    while (line_start < file_end) {
        const char       *line_end = (const char *)memchr(line_start, '\n',
                                                          (size_t)(file_end - line_start));
        size_t             line_len;
        usbs_signature_t   entry;
        line_result_t      result;

        if (line_end == NULL) {
            line_end = file_end;
        }
        line_len = (size_t)(line_end - line_start);
        ++line_no;

        memset(&entry, 0, sizeof(entry));
        result = parse_line(line_start, line_len, &entry);

        if (result == LINE_OK) {
            usbs_status_t push_status = push_entry(list, &entry);
            if (!usbs_ok(push_status)) {
                USBS_LOG_W("signature list: out of memory loading %s at line %zu; stopping",
                          path, line_no);
                break;
            }
        } else if (result == LINE_MALFORMED) {
            ++skipped;
            if (skipped <= USBS_SIGNATURE_MAX_WARNINGS) {
                USBS_LOG_W("signature list: skipping malformed line %zu in %s", line_no, path);
            }
        }

        line_start = (line_end < file_end) ? line_end + 1 : file_end;
    }

    free(buf);

    if (skipped > 0) {
        USBS_LOG_W("signature list: %zu malformed line(s) skipped in %s", skipped, path);
    }
    USBS_LOG_I("signature list: %zu entries loaded from %s", list->count, path);

    qsort(list->entries, list->count, sizeof(usbs_signature_t), compare_by_size);
    return USBS_OK;
}

/* Binary search for the first entry with size >= size_bytes (a lower bound).
 * Shared by lookup() and has_size(): both need exactly this starting point
 * into the size-sorted array before doing their own (different) work on the
 * contiguous run of entries that follow it. */
static size_t lower_bound_by_size(const usbs_signature_list_t *list, usbs_u64 size_bytes)
{
    size_t lo = 0;
    size_t hi = list->count;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (list->entries[mid].size < size_bytes) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

const char *usbs_signature_list_lookup(const usbs_signature_list_t *list,
                                       usbs_u64                     size_bytes,
                                       const char                  *sha256_hex)
{
    size_t lo;
    size_t i;

    if (list == NULL || sha256_hex == NULL || list->count == 0) {
        return NULL;
    }

    /* The run of entries with size == size_bytes, starting at the lower
     * bound, is the whole candidate set - never the full list. */
    lo = lower_bound_by_size(list, size_bytes);
    for (i = lo; i < list->count && list->entries[i].size == size_bytes; ++i) {
        if (strcmp(list->entries[i].sha256_hex, sha256_hex) == 0) {
            return list->entries[i].name;
        }
    }
    return NULL;
}

usbs_bool usbs_signature_list_has_size(const usbs_signature_list_t *list, usbs_u64 size_bytes)
{
    size_t lo;

    if (list == NULL || list->count == 0) {
        return false;
    }
    lo = lower_bound_by_size(list, size_bytes);
    return lo < list->count && list->entries[lo].size == size_bytes;
}
