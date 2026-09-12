/*
 * USB Sentinel - minimal JSON writer and reader.
 *
 * Purpose-built for this project's two real consumers: `reporting` (writes
 * scan reports; ARCHITECTURE.md section 7.4) and `storage` (writes and reads
 * back index.json; ARCHITECTURE.md section 8). Not a general-purpose parser
 * library and not meant to become one - see ARCHITECTURE.md's stance in
 * section 6 on not building abstractions before a second real caller needs
 * them.
 *
 * Portable C17, no platform headers.
 */
#ifndef USBSENTINEL_JSON_H
#define USBSENTINEL_JSON_H

#include <stddef.h>

#include "usbsentinel/error.h"
#include "usbsentinel/types.h"

/* ---------------------------------------------------------------------- *
 * Writer: streaming, append-only. Comma/bracket bookkeeping is automatic;
 * callers just say what comes next. Errors (allocation failure, misuse such
 * as a bare value outside any container) are sticky - once set, further
 * calls are no-ops and usbs_json_writer_finish() reports the failure.
 * ---------------------------------------------------------------------- */

#define USBS_JSON_MAX_DEPTH 32

typedef struct usbs_json_writer {
    char  *buf;
    size_t len;
    size_t cap;

    int       depth;
    usbs_bool is_object[USBS_JSON_MAX_DEPTH]; /* true=object, false=array */
    usbs_bool need_comma[USBS_JSON_MAX_DEPTH];
    usbs_bool want_key[USBS_JSON_MAX_DEPTH]; /* object levels: key next? */

    usbs_status_t error;
} usbs_json_writer_t;

void usbs_json_writer_init(usbs_json_writer_t *w);
void usbs_json_writer_free(usbs_json_writer_t *w);

void usbs_json_begin_object(usbs_json_writer_t *w);
void usbs_json_end_object(usbs_json_writer_t *w);
void usbs_json_begin_array(usbs_json_writer_t *w);
void usbs_json_end_array(usbs_json_writer_t *w);

/* Valid only immediately inside an object, before its value. */
void usbs_json_key(usbs_json_writer_t *w, const char *key);

void usbs_json_string(usbs_json_writer_t *w, const char *value);
void usbs_json_int(usbs_json_writer_t *w, long long value);
void usbs_json_uint(usbs_json_writer_t *w, unsigned long long value);
void usbs_json_bool_value(usbs_json_writer_t *w, usbs_bool value);
void usbs_json_null(usbs_json_writer_t *w);

/* key + value in one call; valid only immediately inside an object. */
void usbs_json_member_string(usbs_json_writer_t *w, const char *key, const char *value);
void usbs_json_member_int(usbs_json_writer_t *w, const char *key, long long value);
void usbs_json_member_uint(usbs_json_writer_t *w, const char *key, unsigned long long value);
void usbs_json_member_bool(usbs_json_writer_t *w, const char *key, usbs_bool value);

/*
 * Finalizes the document. Fails if any container was left open or the writer
 * already carries a sticky error. On success, *out_text points into the
 * writer's own buffer (NUL-terminated) and stays valid until
 * usbs_json_writer_free(); *out_len excludes the terminator.
 */
usbs_status_t usbs_json_writer_finish(usbs_json_writer_t *w,
                                      const char         **out_text,
                                      size_t               *out_len);

/* ---------------------------------------------------------------------- *
 * Reader: parses into a small DOM. Scoped to what index.json needs -
 * objects, arrays, strings, numbers, booleans, null. Depth-limited against
 * a hostile or corrupt file.
 * ---------------------------------------------------------------------- */

typedef enum usbs_json_type {
    USBS_JSON_NULL = 0,
    USBS_JSON_BOOL,
    USBS_JSON_NUMBER,
    USBS_JSON_STRING,
    USBS_JSON_ARRAY,
    USBS_JSON_OBJECT
} usbs_json_type_t;

typedef struct usbs_json_value usbs_json_value_t;

/*
 * Parses `text` (length `len`, need not be NUL-terminated). On success,
 * *out_value owns a tree that must be released with usbs_json_free().
 * On failure (malformed JSON, depth exceeded, allocation failure) returns a
 * non-OK status and leaves *out_value untouched.
 */
usbs_status_t usbs_json_parse(const char          *text,
                              size_t               len,
                              usbs_json_value_t **out_value);

void usbs_json_free(usbs_json_value_t *value);

usbs_json_type_t usbs_json_type(const usbs_json_value_t *value);

/* NULL if `object` is not an object or has no such key. */
const usbs_json_value_t *usbs_json_object_get(const usbs_json_value_t *object,
                                              const char              *key);
size_t usbs_json_object_count(const usbs_json_value_t *object);
const char *usbs_json_object_key_at(const usbs_json_value_t *object, size_t index);
const usbs_json_value_t *usbs_json_object_value_at(const usbs_json_value_t *object,
                                                   size_t                   index);

size_t usbs_json_array_count(const usbs_json_value_t *array);
const usbs_json_value_t *usbs_json_array_at(const usbs_json_value_t *array, size_t index);

/* NULL if `value` is not a string. */
const char *usbs_json_as_string(const usbs_json_value_t *value);
/* False (out untouched) if `value` is not a number, or not integral. */
usbs_bool usbs_json_as_int(const usbs_json_value_t *value, long long *out);
usbs_bool usbs_json_as_bool(const usbs_json_value_t *value, usbs_bool *out);

#endif /* USBSENTINEL_JSON_H */
