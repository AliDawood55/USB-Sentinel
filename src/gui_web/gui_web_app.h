/*
 * USB Sentinel - Phase 16: the web GUI's route handlers, wiring
 * http_server.h's request/response plumbing to the exact same scan
 * engine the CLI and Win32 GUI already use - src/gui/gui_worker.h for
 * orchestration, usbs_report_build_json() for the report body, so this
 * is a fourth consumer of that one engine, never a second
 * implementation of it (ARCHITECTURE.md section 7.4's "never a second
 * source of truth", extended here to scan orchestration itself).
 *
 * Module-internal, like gui_worker.h: not part of the cross-module
 * surface in include/usbsentinel/.
 */
#ifndef USBS_GUI_WEB_APP_H
#define USBS_GUI_WEB_APP_H

#include "http_server.h"
#include "usbsentinel/storage.h"
#include "usbsentinel/types.h"

typedef struct gui_web_app gui_web_app_t;

/*
 * Creates the app's shared state. `token` must already be a NUL-
 * terminated string made only of unreserved URL characters (see
 * app_gui_web/main.c's generator) - this module trusts that and does
 * not re-validate it. `port` is this server's own bound port, used to
 * build the exact "127.0.0.1:<port>" / "localhost:<port>" strings every
 * request's Host header is checked against (the DNS-rebinding
 * mitigation described in ARCHITECTURE.md section 22). `*store` is
 * copied by value (usbs_store_t is a small POD, like usbs_device_t).
 */
usbs_status_t gui_web_app_create(gui_web_app_t **out_app, const char *token,
                                 const usbs_store_t *store, unsigned short port);

/*
 * Requests any in-flight scan to cancel and waits (bounded to a few
 * seconds) for it to actually stop, so no worker-thread callback can
 * fire after gui_web_app_free() below has torn down the state it
 * would write into. Call this before gui_web_app_free(), never after.
 */
void gui_web_app_shutdown(gui_web_app_t *app);

/* NULL-safe. Call only after gui_web_app_shutdown() has returned. */
void gui_web_app_free(gui_web_app_t *app);

/* The http_handler_fn to hand to http_server_run(). */
void gui_web_app_handle_request(void *ctx, const http_request_t *request, int client_fd);

#endif /* USBS_GUI_WEB_APP_H */
