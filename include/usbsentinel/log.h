/*
 * USB Sentinel - leveled logger.
 *
 * Deliberately minimal for Phase 1: one global sink writing to stderr, one
 * runtime level threshold. No sink abstraction, no file rotation, no threading
 * guarantees yet - those arrive only when a real caller needs them.
 */
#ifndef USBSENTINEL_LOG_H
#define USBSENTINEL_LOG_H

#include <stdio.h>

#include "usbsentinel/types.h"

typedef enum usbs_log_level {
    USBS_LOG_TRACE = 0,
    USBS_LOG_DEBUG,
    USBS_LOG_INFO,
    USBS_LOG_WARN,
    USBS_LOG_ERROR,

    /* Suppresses all output when used as the threshold. */
    USBS_LOG_OFF
} usbs_log_level_t;

/*
 * Sets the minimum level that will be emitted. Messages below it are dropped.
 * Default threshold is USBS_LOG_INFO.
 */
void usbs_log_set_level(usbs_log_level_t level);

/* Returns the current threshold. */
usbs_log_level_t usbs_log_get_level(void);

/*
 * Redirects log output. Passing NULL restores the default (stderr). The stream
 * is borrowed, not owned: the caller keeps responsibility for closing it.
 */
void usbs_log_set_stream(FILE *stream);

/* True when a message at `level` would currently be emitted. */
usbs_bool usbs_log_enabled(usbs_log_level_t level);

/* Returns the short uppercase name of `level`, e.g. "INFO". Never NULL. */
const char *usbs_log_level_string(usbs_log_level_t level);

/* Formats and writes one log line. Dropped if `level` is below the threshold. */
void usbs_log_write(usbs_log_level_t level, const char *fmt, ...);

#define USBS_LOG_T(...) usbs_log_write(USBS_LOG_TRACE, __VA_ARGS__)
#define USBS_LOG_D(...) usbs_log_write(USBS_LOG_DEBUG, __VA_ARGS__)
#define USBS_LOG_I(...) usbs_log_write(USBS_LOG_INFO, __VA_ARGS__)
#define USBS_LOG_W(...) usbs_log_write(USBS_LOG_WARN, __VA_ARGS__)
#define USBS_LOG_E(...) usbs_log_write(USBS_LOG_ERROR, __VA_ARGS__)

#endif /* USBSENTINEL_LOG_H */
