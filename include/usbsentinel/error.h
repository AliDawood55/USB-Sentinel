/*
 * USB Sentinel - status codes.
 *
 * Error model: every fallible function returns usbs_status_t and delivers its
 * result through pointer out-parameters. There is no errno-style global state
 * and no exception-like control flow.
 */
#ifndef USBSENTINEL_ERROR_H
#define USBSENTINEL_ERROR_H

#include "usbsentinel/types.h"

typedef enum usbs_status {
    USBS_OK = 0,
    USBS_ERR_INVALID_ARG,
    USBS_ERR_NOT_FOUND,
    USBS_ERR_IO,
    USBS_ERR_ACCESS_DENIED,
    USBS_ERR_NO_MEMORY,
    USBS_ERR_UNSUPPORTED,
    USBS_ERR_INTERNAL,

    /* Not a status. Keep last; equals the number of defined codes. */
    USBS_STATUS_COUNT
} usbs_status_t;

/*
 * Returns a stable, human-readable name for `status`. Never returns NULL:
 * an out-of-range value yields "USBS_ERR_UNKNOWN".
 */
const char *usbs_status_string(usbs_status_t status);

/* True when `status` indicates success. */
static inline usbs_bool usbs_ok(usbs_status_t status)
{
    return status == USBS_OK;
}

#endif /* USBSENTINEL_ERROR_H */
