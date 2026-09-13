/*
 * See gui_web_app.h.
 *
 * Concurrency model: http_server_run()'s accept loop is single-
 * threaded (http_server.c's own module comment), so at most one
 * gui_web_app_handle_request() call is ever executing at a time - the
 * mutex below exists to synchronize with the ONE other thread that
 * touches this state, a scan's own worker thread (progress/completion
 * callbacks), not to serialize concurrent requests against each other
 * (there are none). One consequence worth stating explicitly: a
 * completed scan's usbs_scan_result_t is only ever replaced by
 * gui_web_app_handle_scan_start() freeing the previous one - which,
 * like every other request, cannot run concurrently with whatever
 * request is already reading that same result (e.g. GET /api/report
 * mid-response) - so it is safe to read app->done_result under the
 * lock, then use the pointer after unlocking, for the duration of one
 * request.
 */
#include "gui_web_app.h"

#include <pthread.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "gui_worker.h" /* src/gui/ - module-internal, not include/usbsentinel/ */

#include "usbsentinel/device.h"
#include "usbsentinel/json.h"
#include "usbsentinel/platform.h"
#include "usbsentinel/report.h"

/* Generated at build time from assets/index.html - see CMakeLists.txt. */
extern const unsigned char gui_web_index_html[];
extern const size_t        gui_web_index_html_len;

struct gui_web_app {
    char         token[65];
    usbs_store_t store;
    char         expected_host[64];           /* "127.0.0.1:<port>" */
    char         expected_host_localhost[64]; /* "localhost:<port>" */

    pthread_mutex_t       mutex;
    usbs_bool             busy;
    gui_cancel_flag_t     cancel_flag;
    usbs_scan_progress_t  progress;
    usbs_bool             done;
    usbs_status_t         done_status;
    usbs_scan_result_t   *done_result; /* NULL until a scan finishes; owned here */
};

usbs_status_t gui_web_app_create(gui_web_app_t **out_app, const char *token,
                                 const usbs_store_t *store, unsigned short port)
{
    gui_web_app_t *app;

    if (out_app == NULL || token == NULL || store == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    app = (gui_web_app_t *)calloc(1, sizeof(*app));
    if (app == NULL) {
        return USBS_ERR_NO_MEMORY;
    }

    snprintf(app->token, sizeof(app->token), "%s", token);
    app->store = *store;
    snprintf(app->expected_host, sizeof(app->expected_host), "127.0.0.1:%u", (unsigned)port);
    snprintf(app->expected_host_localhost, sizeof(app->expected_host_localhost),
             "localhost:%u", (unsigned)port);
    gui_cancel_flag_init(&app->cancel_flag);

    if (pthread_mutex_init(&app->mutex, NULL) != 0) {
        free(app);
        return USBS_ERR_INTERNAL;
    }

    *out_app = app;
    return USBS_OK;
}

/* Caller must hold app->mutex. */
static void free_done_result_locked(gui_web_app_t *app)
{
    if (app->done_result != NULL) {
        usbs_scan_result_free(app->done_result);
        free(app->done_result);
        app->done_result = NULL;
    }
}

void gui_web_app_shutdown(gui_web_app_t *app)
{
    enum { MAX_WAIT_MS = 5000, POLL_MS = 50 };
    int waited_ms = 0;

    if (app == NULL) {
        return;
    }

    pthread_mutex_lock(&app->mutex);
    if (app->busy) {
        gui_cancel_flag_set(&app->cancel_flag);
    }
    pthread_mutex_unlock(&app->mutex);

    /* Poll rather than pthread_join(): the worker thread detaches
     * itself immediately (worker_thread_main() below) so its kernel
     * resources are reclaimed as soon as it exits, for every scan over
     * a long GUI session, not just the last one - which means there is
     * no joinable handle left by the time shutdown runs. Bounded so a
     * scan stuck on a single slow/unresponsive file read cannot hang
     * process shutdown forever; the OS reclaims the detached thread's
     * resources regardless of whether this loop waited for it.
     *
     * nanosleep(), not the simpler usleep(): usleep() was removed from
     * POSIX.1-2008 and glibc hides its declaration under this
     * project's own _POSIX_C_SOURCE=200809L (CMakeLists.txt) - confirmed
     * by hitting exactly that implicit-declaration warning while
     * building this file, not assumed from documentation. */
    for (;;) {
        usbs_bool       still_busy;
        struct timespec poll_interval;

        pthread_mutex_lock(&app->mutex);
        still_busy = app->busy;
        pthread_mutex_unlock(&app->mutex);

        if (!still_busy || waited_ms >= MAX_WAIT_MS) {
            break;
        }
        poll_interval.tv_sec  = POLL_MS / 1000;
        poll_interval.tv_nsec = (POLL_MS % 1000) * 1000000L;
        nanosleep(&poll_interval, NULL);
        waited_ms += POLL_MS;
    }
}

void gui_web_app_free(gui_web_app_t *app)
{
    if (app == NULL) {
        return;
    }
    pthread_mutex_lock(&app->mutex);
    free_done_result_locked(app);
    pthread_mutex_unlock(&app->mutex);
    pthread_mutex_destroy(&app->mutex);
    free(app);
}

/* --- auth: token + Host header, applied to every route uniformly --- */

static usbs_bool request_is_authorized(const gui_web_app_t *app, const http_request_t *request)
{
    const char *host = http_request_header(request, "Host");
    const char *token_header;
    char        token_query[128];

    if (host == NULL) {
        return false;
    }
    if (strcmp(host, app->expected_host) != 0 &&
        strcmp(host, app->expected_host_localhost) != 0) {
        return false; /* wrong Host - the DNS-rebinding mitigation */
    }

    token_header = http_request_header(request, "X-USBSentinel-Token");
    if (token_header != NULL && strcmp(token_header, app->token) == 0) {
        return true;
    }
    /* The very first request (the browser opening the launch URL) has
     * no chance to set a header yet, so the token travels as a query
     * parameter there; every request the page's own JS makes after
     * that uses the header instead (see assets/index.html) - a plain
     * HTML form action or an <img> tag from a different origin cannot
     * set a custom header, which is exactly the CSRF resistance the
     * header form is chosen for. */
    if (http_query_get(request->query, "token", token_query, sizeof(token_query)) &&
        strcmp(token_query, app->token) == 0) {
        return true;
    }
    return false;
}

/* --- device enumeration + JSON --- */

static void write_device_json(usbs_json_writer_t *w, const usbs_device_t *device)
{
    char   identity[USBS_IDENTITY_MAX];
    char   safe_id[USBS_IDENTITY_MAX * 3 + 1]; /* worst case: every byte becomes "_XX" */
    size_t i;

    if (!usbs_ok(usbs_device_identity(device, identity, sizeof(identity)))) {
        identity[0] = '\0';
    }
    if (!usbs_ok(usbs_store_safe_id(identity, safe_id, sizeof(safe_id)))) {
        safe_id[0] = '\0';
    }

    usbs_json_begin_object(w);
    usbs_json_member_string(w, "safe_id", safe_id);
    usbs_json_member_string(w, "identity", identity);
    usbs_json_member_string(w, "label", device->label);
    usbs_json_member_string(w, "bus_type", usbs_bus_type_string(device->bus_type));
    usbs_json_member_string(w, "vendor", device->vendor);
    usbs_json_member_string(w, "product", device->product);
    usbs_json_member_string(w, "filesystem", device->filesystem);
    usbs_json_member_uint(w, "capacity_bytes", device->capacity_bytes);
    usbs_json_member_uint(w, "free_bytes", device->free_bytes);
    usbs_json_member_bool(w, "media_present", device->media_present);
    usbs_json_member_bool(w, "scannable", usbs_device_is_scannable_usb(device));

    usbs_json_key(w, "mount_points");
    usbs_json_begin_array(w);
    for (i = 0; i < device->mount_point_count; ++i) {
        usbs_json_string(w, device->mount_points[i]);
    }
    usbs_json_end_array(w);

    usbs_json_end_object(w);
}

static void handle_devices(int client_fd)
{
    usbs_device_source_t source = usbs_platform_device_source();
    usbs_device_list_t   list;
    usbs_json_writer_t   writer;
    const char           *text;
    size_t                len;
    size_t                i;

    if (!usbs_ok(usbs_device_enumerate(&source, &list))) {
        http_send_response(client_fd, 500, "application/json",
                           "{\"error\":\"enumeration failed\"}", 30, NULL);
        return;
    }

    usbs_json_writer_init(&writer);
    usbs_json_begin_array(&writer);
    for (i = 0; i < list.count; ++i) {
        /* Every USB volume, including one with no media present -
         * shown, not hidden, matching the CLI's own "media not
         * present" line (ARCHITECTURE.md section 1's "no silent
         * capability gap"); the frontend disables Scan for it instead
         * of the server deciding not to mention it at all. */
        if (list.items[i].bus_type == USBS_BUS_USB) {
            write_device_json(&writer, &list.items[i]);
        }
    }
    usbs_json_end_array(&writer);

    if (usbs_ok(usbs_json_writer_finish(&writer, &text, &len))) {
        http_send_response(client_fd, 200, "application/json", text, len, NULL);
    } else {
        http_send_response(client_fd, 500, "application/json",
                           "{\"error\":\"serialization failed\"}", 32, NULL);
    }
    usbs_json_writer_free(&writer);
    usbs_device_list_free(&list);
}

static usbs_bool find_device_by_safe_id(const char *safe_id, usbs_device_t *out_device)
{
    usbs_device_source_t source = usbs_platform_device_source();
    usbs_device_list_t   list;
    usbs_bool            found = false;
    size_t               i;

    if (!usbs_ok(usbs_device_enumerate(&source, &list))) {
        return false;
    }
    for (i = 0; i < list.count && !found; ++i) {
        char identity[USBS_IDENTITY_MAX];
        char candidate[USBS_IDENTITY_MAX * 3 + 1];

        if (!usbs_ok(usbs_device_identity(&list.items[i], identity, sizeof(identity)))) {
            continue;
        }
        if (!usbs_ok(usbs_store_safe_id(identity, candidate, sizeof(candidate)))) {
            continue;
        }
        if (strcmp(candidate, safe_id) == 0) {
            *out_device = list.items[i];
            found = true;
        }
    }
    usbs_device_list_free(&list);
    return found;
}

/* --- scanning: reuses src/gui/gui_worker.h directly, on its own thread --- */

typedef struct worker_thread_ctx {
    gui_web_app_t     *app;
    gui_worker_args_t  args;
} worker_thread_ctx_t;

static void on_scan_progress(void *ctx, const usbs_scan_progress_t *progress)
{
    gui_web_app_t *app = (gui_web_app_t *)ctx;
    pthread_mutex_lock(&app->mutex);
    app->progress = *progress;
    pthread_mutex_unlock(&app->mutex);
}

/* Mirrors gui_window.c's save_reports(): the same two files
 * (JSON + CSV) the CLI and Win32 GUI already produce, via the same
 * usbs_store_write_report{,_csv}() calls - never a second on-disk
 * format for the web GUI's own scans. */
static void save_scan_reports(gui_web_app_t *app, const usbs_scan_result_t *result)
{
    char   identity[USBS_IDENTITY_MAX];
    char  *json_text = NULL;
    size_t json_len  = 0;
    char  *csv_text  = NULL;
    size_t csv_len   = 0;
    char   saved_path[USBS_STORE_PATH_MAX];

    if (!usbs_ok(usbs_device_identity(&result->device, identity, sizeof(identity)))) {
        return;
    }

    if (usbs_ok(usbs_report_build_json(result, &json_text, &json_len))) {
        usbs_store_write_report(&app->store, identity, result->scan_id,
                                result->started_at, json_text, json_len,
                                saved_path, sizeof(saved_path));
        free(json_text);
    }
    if (usbs_ok(usbs_report_build_csv(result, &csv_text, &csv_len))) {
        usbs_store_write_report_csv(&app->store, identity, result->scan_id,
                                    result->started_at, csv_text, csv_len,
                                    saved_path, sizeof(saved_path));
        free(csv_text);
    }
}

static void on_scan_done(void *ctx, usbs_status_t status, usbs_scan_result_t *result)
{
    gui_web_app_t *app = (gui_web_app_t *)ctx;

    /* Saved unconditionally on completion, not deferred until (or made
     * conditional on) a browser tab actually fetching /api/report -
     * matching the CLI/Win32 GUI guarantee that a scan's report exists
     * on disk as a side effect of scanning, never of viewing. */
    if (usbs_ok(status) && result != NULL) {
        save_scan_reports(app, result);
    }

    pthread_mutex_lock(&app->mutex);
    free_done_result_locked(app);
    app->done_result = result; /* NULL if status != USBS_OK, which is fine */
    app->done_status  = status;
    app->done          = true;
    app->busy           = false;
    pthread_mutex_unlock(&app->mutex);
}

static void *worker_thread_main(void *arg)
{
    worker_thread_ctx_t *wctx = (worker_thread_ctx_t *)arg;
    /* Detach immediately: see gui_web_app_shutdown()'s comment on why
     * this project polls app->busy instead of pthread_join()-ing a
     * handle that would otherwise need to be kept around (and
     * reclaimed) after every single scan of a long GUI session, not
     * only the last one. */
    pthread_detach(pthread_self());
    gui_worker_run(&wctx->args);
    free(wctx);
    return NULL;
}

/*
 * True only when `device` has a real, walkable scan root: scanner.c
 * walks device->volume_path directly (never mount_points[] itself,
 * which exists for display), so that field is what actually decides
 * whether a scan can even be attempted.
 *
 * Why this check exists here, in the web API layer, rather than in
 * gui_worker.c (the shared orchestration both this and the Win32 GUI
 * use): traced and confirmed by testing against a real unmounted loop
 * device (ARCHITECTURE.md section 22.9) that an empty volume_path does
 * NOT make the scanner fall back to any other path, including the
 * filesystem root - usbs_platform_dir_open("") fails immediately
 * (ENOENT / USBS_ERR_NOT_FOUND), and scanner.c's own depth-0 handling
 * turns that into an immediate, safe scan failure. So the underlying
 * "could this ever scan the wrong thing" risk this guards against does
 * not exist; what does exist is a confusing raw status code
 * ("USBS_ERR_NOT_FOUND") surfacing all the way to the browser for a
 * device the UI should simply have refused to try in the first place -
 * a UX defect, not a safety one. Catching it here, before a worker
 * thread is even spawned, is what lets this function return the exact,
 * human-readable message the frontend shows, which gui_worker_run()'s
 * plain usbs_status_t return value has no room for without changing a
 * signature the Win32 GUI also depends on.
 *
 * The Win32 GUI does not need this same guard today: its device
 * dropdown is filtered by usbs_device_is_scannable_usb() before a
 * device is ever selectable at all. That filter is bus_type + media_
 * present only, not mount state, so it is not a structural guarantee -
 * on Linux specifically, media_present can be true for an unmounted
 * device via a /dev/disk/by-uuid match alone (device_linux.c's own
 * documented asymmetry, ARCHITECTURE.md section 21.2) - which is
 * exactly the gap a real Ubuntu beta test hit through this web API,
 * where there is no dropdown filtering at all before POST /api/scan.
 *
 * Not declared static: exposed the same way
 * usbs_linux_unescape_udev_name() is (no public header, just an extern
 * in the test file) so tests/test_http_server.c can exercise this pure
 * function directly with a plain usbs_device_init()'d fixture - no
 * privilege or real device needed.
 */
usbs_bool device_has_valid_mount_point(const usbs_device_t *device)
{
    if (device->mount_point_count == 0) {
        return false;
    }
    if (device->volume_path[0] == '\0') {
        return false;
    }
    /* Never actually produced by fill_mount_info() today (see the
     * comment above) - kept as an explicit, cheap defense-in-depth
     * check rather than relying solely on that staying true forever. */
    if (strcmp(device->volume_path, "/") == 0) {
        return false;
    }
    return true;
}

static void handle_scan_start(gui_web_app_t *app, const http_request_t *request, int client_fd)
{
    char                  safe_id[256];
    usbs_device_t         device;
    usbs_bool             already_busy;
    worker_thread_ctx_t  *wctx;
    pthread_t             thread;

    if (!http_query_get(request->query, "device", safe_id, sizeof(safe_id))) {
        http_send_response(client_fd, 400, "application/json",
                           "{\"error\":\"missing device parameter\"}", 37, NULL);
        return;
    }

    pthread_mutex_lock(&app->mutex);
    already_busy = app->busy;
    pthread_mutex_unlock(&app->mutex);
    if (already_busy) {
        http_send_response(client_fd, 409, "application/json",
                           "{\"error\":\"a scan is already running\"}", 39, NULL);
        return;
    }

    if (!find_device_by_safe_id(safe_id, &device)) {
        http_send_response(client_fd, 404, "application/json",
                           "{\"error\":\"device not found\"}", 29, NULL);
        return;
    }

    if (!device_has_valid_mount_point(&device)) {
        static const char *const NO_MOUNT_MSG =
            "{\"error\":\"No mount point found for this device. Cannot scan.\"}";
        http_send_response(client_fd, 409, "application/json",
                           NO_MOUNT_MSG, strlen(NO_MOUNT_MSG), NULL);
        return;
    }

    wctx = (worker_thread_ctx_t *)calloc(1, sizeof(*wctx));
    if (wctx == NULL) {
        http_send_response(client_fd, 500, "application/json",
                           "{\"error\":\"out of memory\"}", 26, NULL);
        return;
    }

    pthread_mutex_lock(&app->mutex);
    free_done_result_locked(app);
    gui_cancel_flag_init(&app->cancel_flag);
    memset(&app->progress, 0, sizeof(app->progress));
    app->busy         = true;
    app->done         = false;
    app->done_status  = USBS_OK;
    pthread_mutex_unlock(&app->mutex);

    wctx->app             = app;
    wctx->args.device     = device;
    wctx->args.store      = &app->store;
    wctx->args.cancel_flag = &app->cancel_flag;
    wctx->args.on_progress = on_scan_progress;
    wctx->args.progress_ctx = app;
    wctx->args.on_done     = on_scan_done;
    wctx->args.done_ctx    = app;

    if (pthread_create(&thread, NULL, worker_thread_main, wctx) != 0) {
        free(wctx);
        pthread_mutex_lock(&app->mutex);
        app->busy = false;
        pthread_mutex_unlock(&app->mutex);
        http_send_response(client_fd, 500, "application/json",
                           "{\"error\":\"failed to start scan thread\"}", 41, NULL);
        return;
    }

    http_send_response(client_fd, 202, "application/json", "{\"status\":\"started\"}", 21, NULL);
}

static void handle_progress(gui_web_app_t *app, int client_fd)
{
    usbs_json_writer_t    writer;
    const char           *text;
    size_t                len;
    usbs_bool             busy;
    usbs_bool             done;
    usbs_scan_progress_t  progress;
    usbs_status_t         done_status;

    pthread_mutex_lock(&app->mutex);
    busy        = app->busy;
    done        = app->done;
    progress    = app->progress;
    done_status = app->done_status;
    pthread_mutex_unlock(&app->mutex);

    usbs_json_writer_init(&writer);
    usbs_json_begin_object(&writer);
    usbs_json_member_bool(&writer, "busy", busy);
    usbs_json_member_bool(&writer, "done", done);
    usbs_json_member_uint(&writer, "files_scanned", progress.files_scanned);
    usbs_json_member_uint(&writer, "bytes_scanned", progress.bytes_scanned);
    if (done && !usbs_ok(done_status)) {
        usbs_json_member_string(&writer, "error", usbs_status_string(done_status));
    }
    usbs_json_end_object(&writer);

    if (usbs_ok(usbs_json_writer_finish(&writer, &text, &len))) {
        http_send_response(client_fd, 200, "application/json", text, len, NULL);
    } else {
        http_send_response(client_fd, 500, "application/json", "{}", 2, NULL);
    }
    usbs_json_writer_free(&writer);
}

static void handle_cancel(gui_web_app_t *app, int client_fd)
{
    pthread_mutex_lock(&app->mutex);
    if (app->busy) {
        gui_cancel_flag_set(&app->cancel_flag);
    }
    pthread_mutex_unlock(&app->mutex);
    http_send_response(client_fd, 200, "application/json", "{\"status\":\"ok\"}", 16, NULL);
}

/*
 * Returns report.c's own JSON verbatim - the same schema-versioned
 * document the CLI and Win32 GUI already produce, unwrapped - rather
 * than inventing a second, web-specific report shape. The frontend
 * derives the CLEAN/INCOMPLETE/SUSPICIOUS/THREAT verdict banner from
 * this same JSON in its own JS, mirroring gui_report_view.c's
 * gui_report_summarize() rule (completed AND every check ran AND
 * nothing above "info" severity -> CLEAN) rather than the server
 * duplicating that decision in a second place.
 */
static void handle_report(gui_web_app_t *app, int client_fd)
{
    usbs_scan_result_t *result;
    usbs_bool            done;
    char                *report_json = NULL;
    size_t                report_len = 0;

    pthread_mutex_lock(&app->mutex);
    done   = app->done;
    result = app->done_result;
    pthread_mutex_unlock(&app->mutex);

    if (!done || result == NULL) {
        http_send_response(client_fd, 404, "application/json",
                           "{\"error\":\"no completed scan\"}", 30, NULL);
        return;
    }

    if (!usbs_ok(usbs_report_build_json(result, &report_json, &report_len))) {
        http_send_response(client_fd, 500, "application/json",
                           "{\"error\":\"failed to build report\"}", 35, NULL);
        return;
    }

    http_send_response(client_fd, 200, "application/json", report_json, report_len, NULL);
    free(report_json);
}

void gui_web_app_handle_request(void *ctx, const http_request_t *request, int client_fd)
{
    gui_web_app_t *app = (gui_web_app_t *)ctx;

    if (!request_is_authorized(app, request)) {
        /* Deliberately the same 403 whether the token is missing,
         * wrong, or the Host header doesn't match - giving a different
         * answer for each would help an attacker narrow down which
         * mitigation to attack next. */
        http_send_response(client_fd, 403, "text/plain", "Forbidden", 9, NULL);
        return;
    }

    if (strcmp(request->method, "GET") == 0 && strcmp(request->path, "/") == 0) {
        http_send_response(client_fd, 200, "text/html; charset=utf-8",
                           (const char *)gui_web_index_html, gui_web_index_html_len, NULL);
    } else if (strcmp(request->method, "GET") == 0 && strcmp(request->path, "/api/devices") == 0) {
        handle_devices(client_fd);
    } else if (strcmp(request->method, "POST") == 0 && strcmp(request->path, "/api/scan") == 0) {
        handle_scan_start(app, request, client_fd);
    } else if (strcmp(request->method, "GET") == 0 && strcmp(request->path, "/api/progress") == 0) {
        handle_progress(app, client_fd);
    } else if (strcmp(request->method, "POST") == 0 && strcmp(request->path, "/api/cancel") == 0) {
        handle_cancel(app, client_fd);
    } else if (strcmp(request->method, "GET") == 0 && strcmp(request->path, "/api/report") == 0) {
        handle_report(app, client_fd);
    } else {
        /* Fixed routes only, deliberately - never a generic static-file
         * server (http_server.h's own module comment): any path/method
         * this list does not name is simply Not Found. */
        http_send_response(client_fd, 404, "text/plain", "Not Found", 9, NULL);
    }
}
