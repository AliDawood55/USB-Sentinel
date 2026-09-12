#include <string.h>

#include "test_util.h"
#include "usbsentinel/version.h"

int main(void)
{
    const char *version = usbs_version_string();
    const char *banner  = usbs_version_banner();

    USBS_CHECK(version != NULL);
    USBS_CHECK(banner != NULL);

    USBS_CHECK_STR_EQ(version, USBS_VERSION_STRING);
    USBS_CHECK(strlen(version) > 0);

    /* The banner must name the product and embed the exact version string. */
    USBS_CHECK(strstr(banner, USBS_PRODUCT_NAME) != NULL);
    USBS_CHECK(strstr(banner, version) != NULL);

    /* The numeric macros must reconstruct the string form exactly. */
    {
        char composed[32];
        snprintf(composed, sizeof(composed), "%d.%d.%d",
                 USBS_VERSION_MAJOR, USBS_VERSION_MINOR, USBS_VERSION_PATCH);
        USBS_CHECK_STR_EQ(composed, version);
    }

    return USBS_TEST_RESULT();
}
