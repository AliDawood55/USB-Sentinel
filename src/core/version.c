#include "usbsentinel/version.h"

const char *usbs_version_string(void)
{
    return USBS_VERSION_STRING;
}

const char *usbs_version_banner(void)
{
    return USBS_PRODUCT_NAME " " USBS_VERSION_STRING;
}
