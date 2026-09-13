/*
 * See http_server.h.
 *
 * No percent-decoding anywhere in this file, on purpose: every value
 * this server's own frontend ever sends back to it - a device's
 * usbs_store_safe_id() (alphanumerics, '.', '-', '_' only, by that
 * function's own contract), a scan id (a GUID-shaped string, same
 * restricted alphabet), this server's own hex-encoded launch token -
 * is already made entirely of unreserved URL characters before it
 * ever reaches a query string. A client that only ever needs to send
 * values already in that alphabet never needs to percent-encode them,
 * so this parser never needs to decode them either. If some future
 * caller ever needs to pass a value outside that alphabet (a raw
 * filename, say), a decoder has to be added here before that value
 * can be trusted from this function - do not assume one exists.
 *
 * Single-threaded accept loop, deliberately: each request is a plain
 * read-parse-respond-close cycle taking, in practice, well under a
 * millisecond (the one slow operation, running a scan, happens on its
 * own worker thread started by the handler and never touches this
 * loop again). A single local browser tab issuing sequential fetch()
 * calls has no use for concurrent connection handling, and building it
 * anyway (a thread pool, or select()/poll() multiplexing many
 * connections at once) would be complexity spent on a scale this
 * server will never see - the same "smallest thing that actually
 * solves the problem" judgment ARCHITECTURE.md applies throughout.
 */
#include "http_server.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp */
#include <time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

struct http_server {
    int            listen_fd;
    unsigned short port;
};

/* --- request parsing (pure; no sockets touched below this point) --- */

static void trim_leading_space(const char **s)
{
    while (**s == ' ' || **s == '\t') {
        (*s)++;
    }
}

static usbs_status_t parse_request_line(const char *line, size_t line_len,
                                         http_request_t *out_request)
{
    char        method[HTTP_METHOD_MAX];
    char        full_path[HTTP_PATH_MAX + HTTP_QUERY_MAX];
    char        version[32];
    char        line_buf[HTTP_METHOD_MAX + HTTP_PATH_MAX + HTTP_QUERY_MAX + 40];
    char       *qmark;
    int         matched;

    if (line_len >= sizeof(line_buf)) {
        return USBS_ERR_IO; /* implausibly long request line */
    }
    memcpy(line_buf, line, line_len);
    line_buf[line_len] = '\0';

    /* "METHOD SP path[?query] SP HTTP/x.y" - three whitespace-delimited
     * tokens per RFC 7230 3.1.1. `method`'s width matches its
     * destination exactly (nothing this server matches on is longer
     * than "DELETE"); `full_path` intentionally stays wider than
     * out_request->path/query individually since it holds both,
     * combined, until the '?' split below - each half is bounded again
     * by its own snprintf() once split. */
    matched = sscanf(line_buf, "%7s %511s %31s", method, full_path, version);
    if (matched != 3) {
        return USBS_ERR_IO;
    }

    snprintf(out_request->method, sizeof(out_request->method), "%s", method);

    qmark = strchr(full_path, '?');
    if (qmark != NULL) {
        *qmark = '\0';
        snprintf(out_request->query, sizeof(out_request->query), "%s", qmark + 1);
    }
    snprintf(out_request->path, sizeof(out_request->path), "%s", full_path);

    return USBS_OK;
}

static usbs_status_t parse_header_line(const char *line, size_t line_len,
                                       http_header_t *out_header)
{
    const char *colon;
    const char *value;
    size_t      name_len;
    size_t      value_len;

    colon = memchr(line, ':', line_len);
    if (colon == NULL) {
        return USBS_ERR_IO;
    }
    name_len = (size_t)(colon - line);
    if (name_len >= sizeof(out_header->name)) {
        name_len = sizeof(out_header->name) - 1;
    }
    memcpy(out_header->name, line, name_len);
    out_header->name[name_len] = '\0';

    value = colon + 1;
    trim_leading_space(&value);
    value_len = line_len - (size_t)(value - line);
    if (value_len >= sizeof(out_header->value)) {
        value_len = sizeof(out_header->value) - 1;
    }
    memcpy(out_header->value, value, value_len);
    out_header->value[value_len] = '\0';

    return USBS_OK;
}

usbs_status_t http_request_parse(const char *buf, size_t buf_len,
                                 http_request_t *out_request, size_t *out_head_len)
{
    const char *head_end;
    const char *line_start;
    const char *cursor;
    usbs_status_t status;

    if (buf == NULL || out_request == NULL || out_head_len == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    memset(out_request, 0, sizeof(*out_request));

    head_end = NULL;
    {
        size_t i;
        for (i = 0; i + 3 < buf_len; ++i) {
            if (buf[i] == '\r' && buf[i + 1] == '\n' &&
                buf[i + 2] == '\r' && buf[i + 3] == '\n') {
                head_end = buf + i;
                break;
            }
        }
    }
    if (head_end == NULL) {
        return USBS_ERR_IO; /* caller must buffer until the head is complete */
    }
    *out_head_len = (size_t)(head_end - buf) + 4;

    /* Request line: up to the first "\r\n". */
    line_start = buf;
    cursor = memchr(line_start, '\r', (size_t)(head_end - line_start) + 2);
    if (cursor == NULL) {
        return USBS_ERR_IO;
    }
    status = parse_request_line(line_start, (size_t)(cursor - line_start), out_request);
    if (!usbs_ok(status)) {
        return status;
    }
    line_start = cursor + 2; /* past "\r\n" */

    /* Headers: one per "\r\n"-terminated line until we reach head_end,
     * which is itself the position of the LAST header's own terminating
     * '\r' (head_end marks where the first "\r\n" of the "\r\n\r\n" that
     * ends the head begins) - so the search range needs "+ 1" to include
     * that position instead of stopping just short of it, or the final
     * header line would be silently dropped. */
    while (line_start < head_end) {
        cursor = memchr(line_start, '\r', (size_t)(head_end - line_start) + 1);
        if (cursor == NULL) {
            break;
        }
        if (cursor == line_start) {
            break; /* an empty line before head_end; malformed, stop here */
        }
        if (out_request->header_count < HTTP_MAX_HEADERS) {
            /* A malformed individual header line is skipped rather than
             * failing the whole request - matching device_linux.c's
             * mountinfo parser's stance of skipping one bad line rather
             * than misparsing the rest of a real request a browser
             * actually sent. */
            parse_header_line(line_start, (size_t)(cursor - line_start),
                              &out_request->headers[out_request->header_count]);
            out_request->header_count++;
        }
        line_start = cursor + 2;
    }

    return USBS_OK;
}

const char *http_request_header(const http_request_t *request, const char *name)
{
    size_t i;

    if (request == NULL || name == NULL) {
        return NULL;
    }
    /* strcasecmp: POSIX, not C standard - fine here, this whole module
     * is UNIX-only (root CMakeLists.txt's if(UNIX) gate). */
    for (i = 0; i < request->header_count; ++i) {
        if (strcasecmp(request->headers[i].name, name) == 0) {
            return request->headers[i].value;
        }
    }
    return NULL;
}

usbs_status_t http_request_content_length(const http_request_t *request, size_t *out_len)
{
    const char *value;
    char       *end;
    long long   parsed;

    if (request == NULL || out_len == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    *out_len = 0;

    value = http_request_header(request, "Content-Length");
    if (value == NULL) {
        return USBS_OK; /* absent means "no body" */
    }
    parsed = strtoll(value, &end, 10);
    if (end == value || *end != '\0' || parsed < 0) {
        return USBS_ERR_IO;
    }
    *out_len = (size_t)parsed;
    return USBS_OK;
}

usbs_bool http_query_get(const char *query, const char *key, char *out, size_t out_cap)
{
    size_t key_len;
    const char *cursor;

    if (query == NULL || key == NULL || out == NULL || out_cap == 0) {
        return false;
    }
    out[0] = '\0';
    key_len = strlen(key);
    cursor = query;

    while (*cursor != '\0') {
        const char *amp = strchr(cursor, '&');
        size_t      pair_len = (amp != NULL) ? (size_t)(amp - cursor) : strlen(cursor);

        if (pair_len > key_len && cursor[key_len] == '=' &&
            strncmp(cursor, key, key_len) == 0) {
            const char *value = cursor + key_len + 1;
            size_t      value_len = pair_len - key_len - 1;
            if (value_len >= out_cap) {
                value_len = out_cap - 1;
            }
            memcpy(out, value, value_len);
            out[value_len] = '\0';
            return true;
        }

        cursor += pair_len;
        if (*cursor == '&') {
            cursor++;
        }
    }
    return false;
}

/* --- server: socket I/O --- */

usbs_status_t http_server_start(http_server_t **out_server, unsigned short *out_port)
{
    int                fd;
    struct sockaddr_in addr;
    socklen_t          addr_len = sizeof(addr);
    http_server_t     *server;

    if (out_server == NULL || out_port == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return USBS_ERR_IO;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    /* 127.0.0.1, never INADDR_ANY - the one non-negotiable line in this
     * file's whole security model (ARCHITECTURE.md section 22): this
     * socket must be structurally unreachable from any network, not
     * merely configured to look that way. */
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0); /* ephemeral: let the OS pick, see http_server.h */

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return USBS_ERR_IO;
    }
    if (listen(fd, 8) != 0) {
        close(fd);
        return USBS_ERR_IO;
    }
    if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        close(fd);
        return USBS_ERR_IO;
    }

    server = (http_server_t *)malloc(sizeof(*server));
    if (server == NULL) {
        close(fd);
        return USBS_ERR_NO_MEMORY;
    }
    server->listen_fd = fd;
    server->port = ntohs(addr.sin_port);

    *out_server = server;
    *out_port = server->port;
    return USBS_OK;
}

static void send_all(int fd, const char *data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) {
            return; /* client gone; best-effort only */
        }
        sent += (size_t)n;
    }
}

void http_send_response(int client_fd, int status_code, const char *content_type,
                        const char *body, size_t body_len, const char *extra_headers)
{
    char header[1024];
    const char *status_text;
    int header_len;

    switch (status_code) {
    case 200: status_text = "OK"; break;
    case 202: status_text = "Accepted"; break;
    case 400: status_text = "Bad Request"; break;
    case 403: status_text = "Forbidden"; break;
    case 404: status_text = "Not Found"; break;
    case 405: status_text = "Method Not Allowed"; break;
    case 409: status_text = "Conflict"; break;
    case 413: status_text = "Payload Too Large"; break;
    case 500: status_text = "Internal Server Error"; break;
    default:  status_text = "Error"; break;
    }

    header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        status_code, status_text, content_type, (unsigned long)body_len,
        extra_headers != NULL ? extra_headers : "");

    if (header_len > 0 && (size_t)header_len < sizeof(header)) {
        send_all(client_fd, header, (size_t)header_len);
    }
    if (body != NULL && body_len > 0) {
        send_all(client_fd, body, body_len);
    }
}

/*
 * Reads one full request (head + any body Content-Length declares)
 * into `buf`, then dispatches it to `handler`. A request that never
 * completes its head, or whose declared body would not fit `buf`,
 * gets a plain error response rather than being read forever -
 * bounded, like every buffer read in this project.
 */
static void handle_one_connection(int client_fd, http_handler_fn handler, void *handler_ctx)
{
    enum { REQUEST_BUF_CAP = 65536 };
    char           buf[REQUEST_BUF_CAP];
    size_t         total = 0;
    size_t         head_len = 0;
    size_t         content_length = 0;
    http_request_t request;

    for (;;) {
        ssize_t n;
        if (total >= sizeof(buf) - 1) {
            http_send_response(client_fd, 413, "text/plain", "Request too large", 17, NULL);
            return;
        }
        n = recv(client_fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (n <= 0) {
            return; /* client closed before sending a complete head */
        }
        total += (size_t)n;
        buf[total] = '\0';
        if (memchr(buf, '\r', total) != NULL && strstr(buf, "\r\n\r\n") != NULL) {
            break;
        }
    }

    if (!usbs_ok(http_request_parse(buf, total, &request, &head_len))) {
        http_send_response(client_fd, 400, "text/plain", "Bad Request", 11, NULL);
        return;
    }

    if (!usbs_ok(http_request_content_length(&request, &content_length))) {
        http_send_response(client_fd, 400, "text/plain", "Bad Content-Length", 19, NULL);
        return;
    }
    if (head_len + content_length >= sizeof(buf)) {
        http_send_response(client_fd, 413, "text/plain", "Payload Too Large", 17, NULL);
        return;
    }

    while (total < head_len + content_length) {
        ssize_t n = recv(client_fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (n <= 0) {
            return; /* client closed mid-body */
        }
        total += (size_t)n;
        buf[total] = '\0';
    }

    if (content_length > 0) {
        request.body = buf + head_len;
        request.body_len = content_length;
    }

    handler(handler_ctx, &request, client_fd);
}

void http_server_run(http_server_t *server, http_handler_fn handler, void *handler_ctx,
                     unsigned idle_timeout_secs, const volatile sig_atomic_t *stop_requested)
{
    time_t last_activity;

    if (server == NULL || handler == NULL) {
        return;
    }
    last_activity = time(NULL);

    for (;;) {
        fd_set         readfds;
        struct timeval tv;
        int            ready;
        int            client_fd;

        if (stop_requested != NULL && *stop_requested != 0) {
            break;
        }

        FD_ZERO(&readfds);
        FD_SET(server->listen_fd, &readfds);
        /* A fixed ~1s poll granularity regardless of idle_timeout_secs:
         * this is what lets the stop_requested check above actually
         * notice a request to stop promptly, without this file needing
         * any signal-safety logic of its own (see http_server.h). */
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        ready = select(server->listen_fd + 1, &readfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) {
                continue; /* re-check stop_requested at the top of the loop */
            }
            break; /* e.g. EBADF - the listening socket is gone */
        }
        if (ready == 0) {
            if (idle_timeout_secs > 0 &&
                (unsigned)(time(NULL) - last_activity) >= idle_timeout_secs) {
                break;
            }
            continue;
        }

        client_fd = accept(server->listen_fd, NULL, NULL);
        if (client_fd < 0) {
            continue; /* transient; keep serving */
        }

        handle_one_connection(client_fd, handler, handler_ctx);
        close(client_fd);
        last_activity = time(NULL);
    }
}

void http_server_free(http_server_t *server)
{
    if (server == NULL) {
        return;
    }
    close(server->listen_fd);
    free(server);
}
