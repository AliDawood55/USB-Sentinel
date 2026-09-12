#include "usbsentinel/json.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ======================================================================== *
 * Writer
 * ======================================================================== */

void usbs_json_writer_init(usbs_json_writer_t *w)
{
    if (w == NULL) {
        return;
    }
    memset(w, 0, sizeof(*w));
    w->error = USBS_OK;
}

void usbs_json_writer_free(usbs_json_writer_t *w)
{
    if (w == NULL) {
        return;
    }
    free(w->buf);
    memset(w, 0, sizeof(*w));
}

static void writer_ensure(usbs_json_writer_t *w, size_t extra)
{
    size_t needed;
    size_t new_cap;
    char  *grown;

    if (w->error != USBS_OK) {
        return;
    }

    needed = w->len + extra + 1; /* +1 for a NUL we keep the buffer able to hold */
    if (needed <= w->cap) {
        return;
    }

    new_cap = (w->cap == 0) ? 256 : w->cap;
    while (new_cap < needed) {
        if (new_cap > SIZE_MAX / 2) {
            w->error = USBS_ERR_NO_MEMORY;
            return;
        }
        new_cap *= 2;
    }

    grown = (char *)realloc(w->buf, new_cap);
    if (grown == NULL) {
        w->error = USBS_ERR_NO_MEMORY;
        return;
    }
    w->buf = grown;
    w->cap = new_cap;
}

static void writer_raw(usbs_json_writer_t *w, const char *text, size_t n)
{
    writer_ensure(w, n);
    if (w->error != USBS_OK) {
        return;
    }
    memcpy(w->buf + w->len, text, n);
    w->len += n;
    w->buf[w->len] = '\0';
}

static void writer_raw_str(usbs_json_writer_t *w, const char *text)
{
    writer_raw(w, text, strlen(text));
}

/* Emits the separator a value needs before it is written. Two distinct
 * cases: inside an object, a value always immediately follows its key (the
 * key already wrote any needed comma and the ':' - see usbs_json_key), so no
 * comma belongs here; inside an array (or at the bare top level), a comma is
 * needed before every element but the first. */
static void writer_before_value(usbs_json_writer_t *w)
{
    if (w->error != USBS_OK) {
        return;
    }

    if (w->depth == 0) {
        /* A bare top-level scalar is allowed once; treat like array-less root. */
        return;
    }

    if (w->is_object[w->depth - 1]) {
        if (w->want_key[w->depth - 1]) {
            /* A value was requested without a preceding key. */
            w->error = USBS_ERR_INTERNAL;
            return;
        }
        /* No comma: the key already placed us right after ':'. need_comma
         * stays true (set by usbs_json_key) so the *next* key gets one. */
        w->want_key[w->depth - 1] = true; /* next member needs a key again */
        return;
    }

    /* Array: comma before every element except the first. */
    if (w->need_comma[w->depth - 1]) {
        writer_raw(w, ",", 1);
    }
    w->need_comma[w->depth - 1] = true;
}

static void writer_escape_string(usbs_json_writer_t *w, const char *value)
{
    const unsigned char *p;

    writer_raw(w, "\"", 1);
    for (p = (const unsigned char *)value; *p != '\0'; ++p) {
        switch (*p) {
        case '"':  writer_raw(w, "\\\"", 2); break;
        case '\\': writer_raw(w, "\\\\", 2); break;
        case '\b': writer_raw(w, "\\b", 2); break;
        case '\f': writer_raw(w, "\\f", 2); break;
        case '\n': writer_raw(w, "\\n", 2); break;
        case '\r': writer_raw(w, "\\r", 2); break;
        case '\t': writer_raw(w, "\\t", 2); break;
        default:
            if (*p < 0x20) {
                char esc[8];
                snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)*p);
                writer_raw_str(w, esc);
            } else {
                /* UTF-8 continuation and ASCII bytes pass through unchanged. */
                writer_raw(w, (const char *)p, 1);
            }
        }
        if (w->error != USBS_OK) {
            return;
        }
    }
    writer_raw(w, "\"", 1);
}

void usbs_json_begin_object(usbs_json_writer_t *w)
{
    if (w == NULL || w->error != USBS_OK) {
        return;
    }
    writer_before_value(w);
    if (w->error != USBS_OK) {
        return;
    }
    if (w->depth >= USBS_JSON_MAX_DEPTH) {
        w->error = USBS_ERR_UNSUPPORTED;
        return;
    }
    writer_raw(w, "{", 1);
    w->is_object[w->depth]   = true;
    w->need_comma[w->depth]  = false;
    w->want_key[w->depth]    = true;
    ++w->depth;
}

void usbs_json_end_object(usbs_json_writer_t *w)
{
    if (w == NULL || w->error != USBS_OK) {
        return;
    }
    if (w->depth == 0 || !w->is_object[w->depth - 1]) {
        w->error = USBS_ERR_INTERNAL;
        return;
    }
    --w->depth;
    writer_raw(w, "}", 1);
}

void usbs_json_begin_array(usbs_json_writer_t *w)
{
    if (w == NULL || w->error != USBS_OK) {
        return;
    }
    writer_before_value(w);
    if (w->error != USBS_OK) {
        return;
    }
    if (w->depth >= USBS_JSON_MAX_DEPTH) {
        w->error = USBS_ERR_UNSUPPORTED;
        return;
    }
    writer_raw(w, "[", 1);
    w->is_object[w->depth]  = false;
    w->need_comma[w->depth] = false;
    ++w->depth;
}

void usbs_json_end_array(usbs_json_writer_t *w)
{
    if (w == NULL || w->error != USBS_OK) {
        return;
    }
    if (w->depth == 0 || w->is_object[w->depth - 1]) {
        w->error = USBS_ERR_INTERNAL;
        return;
    }
    --w->depth;
    writer_raw(w, "]", 1);
}

void usbs_json_key(usbs_json_writer_t *w, const char *key)
{
    if (w == NULL || w->error != USBS_OK || key == NULL) {
        return;
    }
    if (w->depth == 0 || !w->is_object[w->depth - 1] || !w->want_key[w->depth - 1]) {
        w->error = USBS_ERR_INTERNAL;
        return;
    }
    if (w->need_comma[w->depth - 1]) {
        writer_raw(w, ",", 1);
    }
    writer_escape_string(w, key);
    writer_raw(w, ":", 1);
    w->want_key[w->depth - 1]   = false;
    w->need_comma[w->depth - 1] = true;
}

void usbs_json_string(usbs_json_writer_t *w, const char *value)
{
    if (w == NULL || w->error != USBS_OK) {
        return;
    }
    writer_before_value(w);
    if (w->error != USBS_OK) {
        return;
    }
    writer_escape_string(w, value != NULL ? value : "");
}

void usbs_json_int(usbs_json_writer_t *w, long long value)
{
    char text[32];
    if (w == NULL || w->error != USBS_OK) {
        return;
    }
    writer_before_value(w);
    if (w->error != USBS_OK) {
        return;
    }
    snprintf(text, sizeof(text), "%lld", value);
    writer_raw_str(w, text);
}

void usbs_json_uint(usbs_json_writer_t *w, unsigned long long value)
{
    char text[32];
    if (w == NULL || w->error != USBS_OK) {
        return;
    }
    writer_before_value(w);
    if (w->error != USBS_OK) {
        return;
    }
    snprintf(text, sizeof(text), "%llu", value);
    writer_raw_str(w, text);
}

void usbs_json_bool_value(usbs_json_writer_t *w, usbs_bool value)
{
    if (w == NULL || w->error != USBS_OK) {
        return;
    }
    writer_before_value(w);
    if (w->error != USBS_OK) {
        return;
    }
    writer_raw_str(w, value ? "true" : "false");
}

void usbs_json_null(usbs_json_writer_t *w)
{
    if (w == NULL || w->error != USBS_OK) {
        return;
    }
    writer_before_value(w);
    if (w->error != USBS_OK) {
        return;
    }
    writer_raw_str(w, "null");
}

void usbs_json_member_string(usbs_json_writer_t *w, const char *key, const char *value)
{
    usbs_json_key(w, key);
    usbs_json_string(w, value);
}

void usbs_json_member_int(usbs_json_writer_t *w, const char *key, long long value)
{
    usbs_json_key(w, key);
    usbs_json_int(w, value);
}

void usbs_json_member_uint(usbs_json_writer_t *w, const char *key, unsigned long long value)
{
    usbs_json_key(w, key);
    usbs_json_uint(w, value);
}

void usbs_json_member_bool(usbs_json_writer_t *w, const char *key, usbs_bool value)
{
    usbs_json_key(w, key);
    usbs_json_bool_value(w, value);
}

usbs_status_t usbs_json_writer_finish(usbs_json_writer_t *w,
                                      const char         **out_text,
                                      size_t               *out_len)
{
    if (w == NULL || out_text == NULL || out_len == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (w->error != USBS_OK) {
        return w->error;
    }
    if (w->depth != 0) {
        return USBS_ERR_INTERNAL; /* unclosed container */
    }
    if (w->buf == NULL) {
        return USBS_ERR_INTERNAL; /* nothing was ever written */
    }
    *out_text = w->buf;
    *out_len  = w->len;
    return USBS_OK;
}

/* ======================================================================== *
 * Reader
 * ======================================================================== */

struct usbs_json_member {
    char              *key;
    usbs_json_value_t *value;
};

struct usbs_json_value {
    usbs_json_type_t type;
    union {
        usbs_bool boolean;
        double    number;
        char     *string;
        struct {
            usbs_json_value_t **items;
            size_t              count;
            size_t              capacity;
        } array;
        struct {
            struct usbs_json_member *items;
            size_t                   count;
            size_t                   capacity;
        } object;
    } u;
};

#define USBS_JSON_PARSE_MAX_DEPTH 32

typedef struct parser {
    const char *text;
    size_t      len;
    size_t      pos;
    int         depth;
} parser_t;

static usbs_status_t parse_value(parser_t *p, usbs_json_value_t **out);

static void skip_ws(parser_t *p)
{
    while (p->pos < p->len) {
        char c = p->text[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            ++p->pos;
        } else {
            break;
        }
    }
}

static usbs_bool at_end(parser_t *p)
{
    return p->pos >= p->len;
}

static char peek(parser_t *p)
{
    return at_end(p) ? '\0' : p->text[p->pos];
}

static usbs_json_value_t *value_new(usbs_json_type_t type)
{
    usbs_json_value_t *v = (usbs_json_value_t *)calloc(1, sizeof(*v));
    if (v != NULL) {
        v->type = type;
    }
    return v;
}

void usbs_json_free(usbs_json_value_t *value)
{
    size_t i;

    if (value == NULL) {
        return;
    }

    switch (value->type) {
    case USBS_JSON_STRING:
        free(value->u.string);
        break;
    case USBS_JSON_ARRAY:
        for (i = 0; i < value->u.array.count; ++i) {
            usbs_json_free(value->u.array.items[i]);
        }
        free(value->u.array.items);
        break;
    case USBS_JSON_OBJECT:
        /* PREfast (/analyze, Phase 12) reports C6001 "using uninitialized
         * memory" for items[i].key here. It cannot see that object_push()
         * (the only writer of u.object.items) always sets .key and .value
         * together before incrementing .count, so every index below .count
         * is genuinely initialized - verified by inspection, not assumed;
         * see object_push() later in this file. A real audit false
         * positive, not a bug:
         * suppressed rather than restructured, since restructuring working,
         * correct code purely to satisfy the analyzer would be the wrong
         * fix for the wrong problem. */
        for (i = 0; i < value->u.object.count; ++i) {
            #pragma warning(suppress : 6001)
            free(value->u.object.items[i].key);
            usbs_json_free(value->u.object.items[i].value);
        }
        free(value->u.object.items);
        break;
    case USBS_JSON_NULL:
    case USBS_JSON_BOOL:
    case USBS_JSON_NUMBER:
        break;
    }
    free(value);
}

/* Parses a JSON string literal starting at the opening quote. On success,
 * *out is a freshly allocated, NUL-terminated, unescaped C string. */
static usbs_status_t parse_string_literal(parser_t *p, char **out)
{
    size_t start;
    size_t cap = 32;
    size_t len = 0;
    char  *buf = (char *)malloc(cap);

    if (buf == NULL) {
        return USBS_ERR_NO_MEMORY;
    }
    if (peek(p) != '"') {
        free(buf);
        return USBS_ERR_INVALID_ARG;
    }
    ++p->pos;
    start = p->pos;
    USBS_UNUSED(start);

    for (;;) {
        char c;

        if (at_end(p)) {
            free(buf);
            return USBS_ERR_INVALID_ARG;
        }
        c = p->text[p->pos++];
        if (c == '"') {
            break;
        }
        if (c == '\\') {
            char esc;
            if (at_end(p)) {
                free(buf);
                return USBS_ERR_INVALID_ARG;
            }
            esc = p->text[p->pos++];
            switch (esc) {
            case '"':  c = '"';  break;
            case '\\': c = '\\'; break;
            case '/':  c = '/';  break;
            case 'b':  c = '\b'; break;
            case 'f':  c = '\f'; break;
            case 'n':  c = '\n'; break;
            case 'r':  c = '\r'; break;
            case 't':  c = '\t'; break;
            case 'u': {
                /* \uXXXX: only the BMP subset is needed for our own output
                 * (control characters); decode into UTF-8 for codepoints up
                 * to 0xFFFF, surrogate pairs included as best-effort. */
                unsigned code = 0;
                int      i;
                if (p->pos + 4 > p->len) {
                    free(buf);
                    return USBS_ERR_INVALID_ARG;
                }
                for (i = 0; i < 4; ++i) {
                    char h = p->text[p->pos++];
                    code <<= 4;
                    if (h >= '0' && h <= '9') {
                        code |= (unsigned)(h - '0');
                    } else if (h >= 'a' && h <= 'f') {
                        code |= (unsigned)(h - 'a' + 10);
                    } else if (h >= 'A' && h <= 'F') {
                        code |= (unsigned)(h - 'A' + 10);
                    } else {
                        free(buf);
                        return USBS_ERR_INVALID_ARG;
                    }
                }
                if (code < 0x80) {
                    if (len + 1 >= cap) {
                        char *grown;
                        cap *= 2;
                        grown = (char *)realloc(buf, cap);
                        if (grown == NULL) {
                            free(buf);
                            return USBS_ERR_NO_MEMORY;
                        }
                        buf = grown;
                    }
                    buf[len++] = (char)code;
                } else {
                    /* Encode as UTF-8 (2 or 3 bytes; surrogates approximate). */
                    char enc[3];
                    size_t n;
                    if (code < 0x800) {
                        enc[0] = (char)(0xC0 | (code >> 6));
                        enc[1] = (char)(0x80 | (code & 0x3F));
                        n = 2;
                    } else {
                        enc[0] = (char)(0xE0 | (code >> 12));
                        enc[1] = (char)(0x80 | ((code >> 6) & 0x3F));
                        enc[2] = (char)(0x80 | (code & 0x3F));
                        n = 3;
                    }
                    if (len + n >= cap) {
                        char *grown;
                        while (len + n >= cap) {
                            cap *= 2;
                        }
                        grown = (char *)realloc(buf, cap);
                        if (grown == NULL) {
                            free(buf);
                            return USBS_ERR_NO_MEMORY;
                        }
                        buf = grown;
                    }
                    memcpy(buf + len, enc, n);
                    len += n;
                }
                continue;
            }
            default:
                free(buf);
                return USBS_ERR_INVALID_ARG;
            }
        }

        if (len + 1 >= cap) {
            char *grown;
            cap *= 2;
            grown = (char *)realloc(buf, cap);
            if (grown == NULL) {
                free(buf);
                return USBS_ERR_NO_MEMORY;
            }
            buf = grown;
        }
        buf[len++] = c;
    }

    buf[len] = '\0';
    *out = buf;
    return USBS_OK;
}

static usbs_status_t parse_number(parser_t *p, double *out)
{
    size_t start = p->pos;
    char  *endptr;
    char   tmp[64];
    size_t n;

    if (peek(p) == '-') {
        ++p->pos;
    }
    while (!at_end(p) && isdigit((unsigned char)peek(p))) {
        ++p->pos;
    }
    if (!at_end(p) && peek(p) == '.') {
        ++p->pos;
        while (!at_end(p) && isdigit((unsigned char)peek(p))) {
            ++p->pos;
        }
    }
    if (!at_end(p) && (peek(p) == 'e' || peek(p) == 'E')) {
        ++p->pos;
        if (!at_end(p) && (peek(p) == '+' || peek(p) == '-')) {
            ++p->pos;
        }
        while (!at_end(p) && isdigit((unsigned char)peek(p))) {
            ++p->pos;
        }
    }

    n = p->pos - start;
    if (n == 0 || n >= sizeof(tmp)) {
        return USBS_ERR_INVALID_ARG;
    }
    memcpy(tmp, p->text + start, n);
    tmp[n] = '\0';

    *out = strtod(tmp, &endptr);
    if (endptr != tmp + n) {
        return USBS_ERR_INVALID_ARG;
    }
    return USBS_OK;
}

static usbs_bool match_literal(parser_t *p, const char *literal)
{
    size_t n = strlen(literal);
    if (p->pos + n > p->len) {
        return false;
    }
    if (memcmp(p->text + p->pos, literal, n) != 0) {
        return false;
    }
    p->pos += n;
    return true;
}

static usbs_status_t object_push(usbs_json_value_t *obj, char *key, usbs_json_value_t *val)
{
    if (obj->u.object.count == obj->u.object.capacity) {
        size_t next = (obj->u.object.capacity == 0) ? 4 : obj->u.object.capacity * 2;
        struct usbs_json_member *grown =
            (struct usbs_json_member *)realloc(obj->u.object.items,
                                               next * sizeof(*grown));
        if (grown == NULL) {
            return USBS_ERR_NO_MEMORY;
        }
        obj->u.object.items    = grown;
        obj->u.object.capacity = next;
    }
    obj->u.object.items[obj->u.object.count].key   = key;
    obj->u.object.items[obj->u.object.count].value = val;
    ++obj->u.object.count;
    return USBS_OK;
}

static usbs_status_t array_push(usbs_json_value_t *arr, usbs_json_value_t *val)
{
    if (arr->u.array.count == arr->u.array.capacity) {
        size_t next = (arr->u.array.capacity == 0) ? 4 : arr->u.array.capacity * 2;
        usbs_json_value_t **grown =
            (usbs_json_value_t **)realloc(arr->u.array.items, next * sizeof(*grown));
        if (grown == NULL) {
            return USBS_ERR_NO_MEMORY;
        }
        arr->u.array.items    = grown;
        arr->u.array.capacity = next;
    }
    arr->u.array.items[arr->u.array.count++] = val;
    return USBS_OK;
}

static usbs_status_t parse_object(parser_t *p, usbs_json_value_t **out)
{
    usbs_json_value_t *obj = value_new(USBS_JSON_OBJECT);
    if (obj == NULL) {
        return USBS_ERR_NO_MEMORY;
    }

    ++p->pos; /* consume '{' */
    skip_ws(p);

    if (peek(p) == '}') {
        ++p->pos;
        *out = obj;
        return USBS_OK;
    }

    for (;;) {
        char              *key;
        usbs_json_value_t *val;
        usbs_status_t      status;

        skip_ws(p);
        status = parse_string_literal(p, &key);
        if (!usbs_ok(status)) {
            usbs_json_free(obj);
            return status;
        }

        skip_ws(p);
        if (peek(p) != ':') {
            free(key);
            usbs_json_free(obj);
            return USBS_ERR_INVALID_ARG;
        }
        ++p->pos;
        skip_ws(p);

        status = parse_value(p, &val);
        if (!usbs_ok(status)) {
            free(key);
            usbs_json_free(obj);
            return status;
        }

        status = object_push(obj, key, val);
        if (!usbs_ok(status)) {
            free(key);
            usbs_json_free(val);
            usbs_json_free(obj);
            return status;
        }

        skip_ws(p);
        if (peek(p) == ',') {
            ++p->pos;
            continue;
        }
        if (peek(p) == '}') {
            ++p->pos;
            break;
        }
        usbs_json_free(obj);
        return USBS_ERR_INVALID_ARG;
    }

    *out = obj;
    return USBS_OK;
}

static usbs_status_t parse_array(parser_t *p, usbs_json_value_t **out)
{
    usbs_json_value_t *arr = value_new(USBS_JSON_ARRAY);
    if (arr == NULL) {
        return USBS_ERR_NO_MEMORY;
    }

    ++p->pos; /* consume '[' */
    skip_ws(p);

    if (peek(p) == ']') {
        ++p->pos;
        *out = arr;
        return USBS_OK;
    }

    for (;;) {
        usbs_json_value_t *val;
        usbs_status_t      status;

        skip_ws(p);
        status = parse_value(p, &val);
        if (!usbs_ok(status)) {
            usbs_json_free(arr);
            return status;
        }

        status = array_push(arr, val);
        if (!usbs_ok(status)) {
            usbs_json_free(val);
            usbs_json_free(arr);
            return status;
        }

        skip_ws(p);
        if (peek(p) == ',') {
            ++p->pos;
            continue;
        }
        if (peek(p) == ']') {
            ++p->pos;
            break;
        }
        usbs_json_free(arr);
        return USBS_ERR_INVALID_ARG;
    }

    *out = arr;
    return USBS_OK;
}

static usbs_status_t parse_value(parser_t *p, usbs_json_value_t **out)
{
    usbs_status_t status;

    if (p->depth >= USBS_JSON_PARSE_MAX_DEPTH) {
        return USBS_ERR_UNSUPPORTED;
    }

    skip_ws(p);
    if (at_end(p)) {
        return USBS_ERR_INVALID_ARG;
    }

    switch (peek(p)) {
    case '{':
        ++p->depth;
        status = parse_object(p, out);
        --p->depth;
        return status;
    case '[':
        ++p->depth;
        status = parse_array(p, out);
        --p->depth;
        return status;
    case '"': {
        char *s;
        status = parse_string_literal(p, &s);
        if (!usbs_ok(status)) {
            return status;
        }
        *out = value_new(USBS_JSON_STRING);
        if (*out == NULL) {
            free(s);
            return USBS_ERR_NO_MEMORY;
        }
        (*out)->u.string = s;
        return USBS_OK;
    }
    case 't':
        if (!match_literal(p, "true")) {
            return USBS_ERR_INVALID_ARG;
        }
        *out = value_new(USBS_JSON_BOOL);
        if (*out == NULL) {
            return USBS_ERR_NO_MEMORY;
        }
        (*out)->u.boolean = true;
        return USBS_OK;
    case 'f':
        if (!match_literal(p, "false")) {
            return USBS_ERR_INVALID_ARG;
        }
        *out = value_new(USBS_JSON_BOOL);
        if (*out == NULL) {
            return USBS_ERR_NO_MEMORY;
        }
        (*out)->u.boolean = false;
        return USBS_OK;
    case 'n':
        if (!match_literal(p, "null")) {
            return USBS_ERR_INVALID_ARG;
        }
        *out = value_new(USBS_JSON_NULL);
        return (*out == NULL) ? USBS_ERR_NO_MEMORY : USBS_OK;
    default:
        if (peek(p) == '-' || isdigit((unsigned char)peek(p))) {
            double number;
            status = parse_number(p, &number);
            if (!usbs_ok(status)) {
                return status;
            }
            *out = value_new(USBS_JSON_NUMBER);
            if (*out == NULL) {
                return USBS_ERR_NO_MEMORY;
            }
            (*out)->u.number = number;
            return USBS_OK;
        }
        return USBS_ERR_INVALID_ARG;
    }
}

usbs_status_t usbs_json_parse(const char *text, size_t len, usbs_json_value_t **out_value)
{
    parser_t      p;
    usbs_status_t status;
    usbs_json_value_t *value = NULL;

    if (text == NULL || out_value == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    p.text  = text;
    p.len   = len;
    p.pos   = 0;
    p.depth = 0;

    status = parse_value(&p, &value);
    if (!usbs_ok(status)) {
        return status;
    }

    skip_ws(&p);
    if (!at_end(&p)) {
        usbs_json_free(value);
        return USBS_ERR_INVALID_ARG; /* trailing garbage */
    }

    *out_value = value;
    return USBS_OK;
}

usbs_json_type_t usbs_json_type(const usbs_json_value_t *value)
{
    return (value != NULL) ? value->type : USBS_JSON_NULL;
}

const usbs_json_value_t *usbs_json_object_get(const usbs_json_value_t *object, const char *key)
{
    size_t i;

    if (object == NULL || object->type != USBS_JSON_OBJECT || key == NULL) {
        return NULL;
    }
    for (i = 0; i < object->u.object.count; ++i) {
        if (strcmp(object->u.object.items[i].key, key) == 0) {
            return object->u.object.items[i].value;
        }
    }
    return NULL;
}

size_t usbs_json_object_count(const usbs_json_value_t *object)
{
    return (object != NULL && object->type == USBS_JSON_OBJECT) ? object->u.object.count : 0;
}

const char *usbs_json_object_key_at(const usbs_json_value_t *object, size_t index)
{
    if (object == NULL || object->type != USBS_JSON_OBJECT || index >= object->u.object.count) {
        return NULL;
    }
    return object->u.object.items[index].key;
}

const usbs_json_value_t *usbs_json_object_value_at(const usbs_json_value_t *object, size_t index)
{
    if (object == NULL || object->type != USBS_JSON_OBJECT || index >= object->u.object.count) {
        return NULL;
    }
    return object->u.object.items[index].value;
}

size_t usbs_json_array_count(const usbs_json_value_t *array)
{
    return (array != NULL && array->type == USBS_JSON_ARRAY) ? array->u.array.count : 0;
}

const usbs_json_value_t *usbs_json_array_at(const usbs_json_value_t *array, size_t index)
{
    if (array == NULL || array->type != USBS_JSON_ARRAY || index >= array->u.array.count) {
        return NULL;
    }
    return array->u.array.items[index];
}

const char *usbs_json_as_string(const usbs_json_value_t *value)
{
    return (value != NULL && value->type == USBS_JSON_STRING) ? value->u.string : NULL;
}

usbs_bool usbs_json_as_int(const usbs_json_value_t *value, long long *out)
{
    double whole;

    if (value == NULL || value->type != USBS_JSON_NUMBER || out == NULL) {
        return false;
    }
    if (modf(value->u.number, &whole) != 0.0) {
        return false;
    }
    *out = (long long)value->u.number;
    return true;
}

usbs_bool usbs_json_as_bool(const usbs_json_value_t *value, usbs_bool *out)
{
    if (value == NULL || value->type != USBS_JSON_BOOL || out == NULL) {
        return false;
    }
    *out = value->u.boolean;
    return true;
}
