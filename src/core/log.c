#include "usbsentinel/log.h"

#include <stdarg.h>
#include <time.h>

static usbs_log_level_t g_level  = USBS_LOG_INFO;
static FILE            *g_stream = NULL;

/* Resolved lazily: stderr is not a compile-time constant on MSVC. */
static FILE *log_stream(void)
{
    return (g_stream != NULL) ? g_stream : stderr;
}

void usbs_log_set_level(usbs_log_level_t level)
{
    g_level = level;
}

usbs_log_level_t usbs_log_get_level(void)
{
    return g_level;
}

void usbs_log_set_stream(FILE *stream)
{
    g_stream = stream;
}

usbs_bool usbs_log_enabled(usbs_log_level_t level)
{
    if (g_level >= USBS_LOG_OFF) {
        return false;
    }
    if (level >= USBS_LOG_OFF) {
        return false;
    }
    return level >= g_level;
}

const char *usbs_log_level_string(usbs_log_level_t level)
{
    switch (level) {
    case USBS_LOG_TRACE: return "TRACE";
    case USBS_LOG_DEBUG: return "DEBUG";
    case USBS_LOG_INFO:  return "INFO";
    case USBS_LOG_WARN:  return "WARN";
    case USBS_LOG_ERROR: return "ERROR";
    case USBS_LOG_OFF:   return "OFF";
    }
    return "UNKNOWN";
}

/* Writes "HH:MM:SS" into `buf`, or "--:--:--" if the clock is unavailable. */
static void format_timestamp(char *buf, size_t cap)
{
    time_t    now = time(NULL);
    struct tm tm_now;
    int       ok;

#if defined(_MSC_VER)
    ok = (localtime_s(&tm_now, &now) == 0);
#else
    ok = (localtime_r(&now, &tm_now) != NULL);
#endif

    if (!ok || strftime(buf, cap, "%H:%M:%S", &tm_now) == 0) {
        snprintf(buf, cap, "--:--:--");
    }
}

void usbs_log_write(usbs_log_level_t level, const char *fmt, ...)
{
    char    stamp[16];
    FILE   *out;
    va_list args;

    if (!usbs_log_enabled(level) || fmt == NULL) {
        return;
    }

    format_timestamp(stamp, sizeof(stamp));

    out = log_stream();
    fprintf(out, "[%s] %-5s ", stamp, usbs_log_level_string(level));

    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);

    fputc('\n', out);
    fflush(out);
}
