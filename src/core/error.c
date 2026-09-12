#include "usbsentinel/error.h"

const char *usbs_status_string(usbs_status_t status)
{
    switch (status) {
    case USBS_OK:                return "USBS_OK";
    case USBS_ERR_INVALID_ARG:   return "USBS_ERR_INVALID_ARG";
    case USBS_ERR_NOT_FOUND:     return "USBS_ERR_NOT_FOUND";
    case USBS_ERR_IO:            return "USBS_ERR_IO";
    case USBS_ERR_ACCESS_DENIED: return "USBS_ERR_ACCESS_DENIED";
    case USBS_ERR_NO_MEMORY:     return "USBS_ERR_NO_MEMORY";
    case USBS_ERR_UNSUPPORTED:   return "USBS_ERR_UNSUPPORTED";
    case USBS_ERR_INTERNAL:      return "USBS_ERR_INTERNAL";
    case USBS_STATUS_COUNT:      break;
    }
    return "USBS_ERR_UNKNOWN";
}
