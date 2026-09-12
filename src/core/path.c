/*
 * Path separator handling. See path.h for why this varies by host rather
 * than settling on "/" everywhere.
 */
#include "usbsentinel/path.h"

#include <stdio.h>
#include <string.h>

usbs_bool usbs_path_is_separator(char c)
{
#if defined(_WIN32)
    return (c == '\\') || (c == '/');
#else
    return c == '/';
#endif
}

usbs_status_t usbs_path_join(char *out, size_t cap, const char *base, const char *leaf)
{
    size_t base_len;
    int    written;

    if (out == NULL || base == NULL || leaf == NULL || cap == 0) {
        return USBS_ERR_INVALID_ARG;
    }

    base_len = strlen(base);

    /* A base that already ends in a separator must not gain a second one:
     * volume_path carries a trailing separator by definition (device.h),
     * while an ordinary directory path does not, and both reach here. */
    if (base_len > 0 && usbs_path_is_separator(base[base_len - 1])) {
        written = snprintf(out, cap, "%s%s", base, leaf);
    } else {
        written = snprintf(out, cap, "%s%s%s", base, USBS_PATH_SEP, leaf);
    }

    if (written < 0) {
        return USBS_ERR_INTERNAL;
    }
    if ((size_t)written >= cap) {
        return USBS_ERR_NO_MEMORY; /* truncated */
    }
    return USBS_OK;
}
