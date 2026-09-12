#include "usbsentinel/env.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

usbs_status_t usbs_getenv(const char *name, char *out, size_t cap)
{
    if (name == NULL || out == NULL || cap == 0) {
        return USBS_ERR_INVALID_ARG;
    }
    out[0] = '\0';

#if defined(_MSC_VER)
    {
        char  *value = NULL;
        size_t value_len = 0;
        errno_t err = _dupenv_s(&value, &value_len, name);
        usbs_status_t status;

        if (err != 0 || value == NULL || value[0] == '\0') {
            free(value);
            return USBS_ERR_NOT_FOUND;
        }
        status = (strlen(value) >= cap) ? USBS_ERR_NO_MEMORY : USBS_OK;
        if (usbs_ok(status)) {
            snprintf(out, cap, "%s", value);
        }
        free(value);
        return status;
    }
#else
    {
        const char *value = getenv(name);
        if (value == NULL || value[0] == '\0') {
            return USBS_ERR_NOT_FOUND;
        }
        if (strlen(value) >= cap) {
            return USBS_ERR_NO_MEMORY;
        }
        snprintf(out, cap, "%s", value);
        return USBS_OK;
    }
#endif
}

usbs_status_t usbs_setenv(const char *name, const char *value)
{
    if (name == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (value == NULL) {
        value = "";
    }

#if defined(_MSC_VER)
    if (_putenv_s(name, value) != 0) {
        return USBS_ERR_INTERNAL;
    }
#else
    if (value[0] == '\0') {
        unsetenv(name);
    } else if (setenv(name, value, 1) != 0) {
        return USBS_ERR_INTERNAL;
    }
#endif
    return USBS_OK;
}
