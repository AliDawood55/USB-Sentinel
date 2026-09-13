/*
 * USB Sentinel - Phase 16: a minimal HTTP/1.1 server over raw POSIX
 * sockets, purpose-built for the web GUI's own tiny, fixed set of
 * routes. Deliberately not a general-purpose HTTP library: no chunked
 * transfer encoding, no keep-alive (every response sends
 * "Connection: close"), no arbitrary path routing - see
 * ARCHITECTURE.md section 22 for why that scope is a deliberate choice
 * ("no third-party dependency" extends to not building one ourselves)
 * and for the security model (loopback-only, per-launch token, Host
 * header validation) every caller of this module must apply.
 *
 * Split in two, like gui_worker.c/gui_report_view.c: request parsing
 * (http_request_parse(), pure and hermetically testable - feed it a
 * byte buffer, assert the result) versus the actual socket I/O
 * (http_server_start()/_run()), which needs a real OS and is exercised
 * by a real end-to-end curl-based CI step instead.
 *
 * Module-internal, like gui_worker.h: not part of the cross-module
 * surface in include/usbsentinel/.
 */
#ifndef USBS_HTTP_SERVER_H
#define USBS_HTTP_SERVER_H

#include <signal.h>
#include <stddef.h>

#include "usbsentinel/error.h"
#include "usbsentinel/types.h"

#define HTTP_METHOD_MAX        8
#define HTTP_PATH_MAX          256
#define HTTP_QUERY_MAX         256
#define HTTP_HEADER_NAME_MAX   64
#define HTTP_HEADER_VALUE_MAX  512
#define HTTP_MAX_HEADERS       16

typedef struct http_header {
    char name[HTTP_HEADER_NAME_MAX];
    char value[HTTP_HEADER_VALUE_MAX];
} http_header_t;

typedef struct http_request {
    char method[HTTP_METHOD_MAX];
    char path[HTTP_PATH_MAX];   /* query string stripped; see the note in
                                  * http_server.c on why this is never
                                  * percent-decoded */
    char query[HTTP_QUERY_MAX]; /* raw, no leading '?'; "" if none */

    http_header_t headers[HTTP_MAX_HEADERS];
    size_t        header_count;

    /* Points into the caller's own read buffer - valid only as long as
     * that buffer is; NULL/0 when the request has no body. Never owned
     * or freed by this struct. */
    const char *body;
    size_t      body_len;
} http_request_t;

/*
 * Parses the request line and headers out of `buf` (`buf_len` bytes,
 * NUL-terminated by the caller). `buf` must already contain the full
 * head - up to and including the blank line ("\r\n\r\n") that ends
 * it; this function does not itself read from a socket or wait for
 * more data. `*out_head_len` receives the byte offset of the body
 * (i.e. how much of `buf` the head consumed) so the caller can slice
 * the rest off as the body once it knows how long that is (see
 * http_request_content_length()).
 *
 * Returns USBS_ERR_INVALID_ARG for a NULL argument, USBS_ERR_IO for a
 * request line/header block that doesn't parse (missing "\r\n\r\n",
 * a request line with fewer than three space-delimited tokens, a
 * header line with no ':') - deliberately a parse failure, not a
 * crash, on anything this file did not anticipate; the caller answers
 * with a plain 400.
 */
usbs_status_t http_request_parse(const char *buf, size_t buf_len,
                                 http_request_t *out_request, size_t *out_head_len);

/* Case-insensitive header lookup (HTTP header names are case-
 * insensitive per RFC 7230). NULL if `name` is not present. */
const char *http_request_header(const http_request_t *request, const char *name);

/*
 * Parses the Content-Length header, if present. *out_len is set to 0
 * and USBS_OK is returned when the header is absent - that means "no
 * body", not an error, matching a plain GET or a bodyless POST.
 * Returns USBS_ERR_IO if the header is present but not a valid
 * non-negative integer.
 */
usbs_status_t http_request_content_length(const http_request_t *request, size_t *out_len);

/*
 * Looks up `key` in `query` (as `http_request_t.query` holds it: raw,
 * "a=1&b=2" shape, no leading '?'). Copies the value into `out` (NUL-
 * terminated, truncated if `out_cap` is too small) and returns true;
 * false if `key` is not present. No percent-decoding is performed -
 * see http_server.c's module comment for why every value this server
 * actually needs to accept (a device's usbs_store_safe_id(), a scan
 * id, this server's own hex token) is already restricted to
 * unreserved URL characters by construction, so a client never needs
 * to percent-encode any of them and this parser never needs to decode
 * them.
 */
usbs_bool http_query_get(const char *query, const char *key, char *out, size_t out_cap);

/* --- Server --- */

typedef struct http_server http_server_t;

/*
 * Called once per accepted, fully-read request, on the server's own
 * thread (http_server_run()'s caller). `client_fd` is open and ready
 * for the handler to write a response to via http_send_response();
 * the server closes it afterward - the handler must not close it
 * itself. Ordinary requests (device list, progress poll, cancel) are
 * always fast; the one exception (starting a scan) hands the actual
 * work to its own worker thread and returns immediately, so no
 * handler may block this loop for the duration of a scan.
 */
typedef void (*http_handler_fn)(void *ctx, const http_request_t *request, int client_fd);

/*
 * Creates a listening socket bound to 127.0.0.1 on an OS-assigned
 * ephemeral port (never 0.0.0.0 - see ARCHITECTURE.md section 22 for
 * why binding only the loopback address is the one non-negotiable
 * part of this module's security model). `*out_port` receives the
 * port actually bound. Returns USBS_ERR_IO on any socket()/bind()/
 * listen() failure.
 */
usbs_status_t http_server_start(http_server_t **out_server, unsigned short *out_port);

/*
 * Runs the accept loop on the calling thread. Returns when
 * `*stop_requested` becomes non-zero (checked roughly once a second,
 * regardless of `idle_timeout_secs` - see http_server.c) or when
 * `idle_timeout_secs` seconds pass with no request served (0 disables
 * the idle timeout; used by tests, which drive the flag directly and
 * do not want a background timeout racing them).
 *
 * `stop_requested` is deliberately a plain flag polled from this
 * loop, not a signal handler owned by this file: this file has no
 * signal-handling code of its own, so a test can stop it by just
 * setting the flag, with no real signal involved. main.c is the one
 * place that actually calls signal()/sigaction() and flips this flag
 * from a handler - see its own comment for why a flag-and-poll design
 * was chosen over closing the socket directly from the handler (the
 * more common trick, and the one this project's own investigation
 * found to be racier than it looks).
 */
void http_server_run(http_server_t *server, http_handler_fn handler, void *handler_ctx,
                     unsigned idle_timeout_secs, const volatile sig_atomic_t *stop_requested);

void http_server_free(http_server_t *server);

/*
 * Writes a complete HTTP/1.1 response to `client_fd`: status line,
 * Content-Type, Content-Length (computed from `body_len`, so callers
 * never get this wrong by hand), "Connection: close", then
 * `extra_headers` verbatim (raw "Name: value\r\n" lines; NULL if
 * none), then the blank line and `body`. Every write goes through an
 * internal send-all loop (send() can do a short write on a real
 * socket), so a large body is never sent partially.
 */
void http_send_response(int client_fd, int status_code, const char *content_type,
                        const char *body, size_t body_len, const char *extra_headers);

#endif /* USBS_HTTP_SERVER_H */
