#include <string.h>

#include "test_util.h"
#include "usbsentinel/error.h"

int main(void)
{
    int i;

    /* Every declared status must map to a distinct, non-placeholder name. */
    for (i = 0; i < (int)USBS_STATUS_COUNT; ++i) {
        const char *name = usbs_status_string((usbs_status_t)i);
        USBS_CHECK(name != NULL);
        USBS_CHECK(strlen(name) > 0);
        USBS_CHECK(strcmp(name, "USBS_ERR_UNKNOWN") != 0);
    }

    /* Names must be unique so log output is unambiguous. */
    for (i = 0; i < (int)USBS_STATUS_COUNT; ++i) {
        int j;
        for (j = i + 1; j < (int)USBS_STATUS_COUNT; ++j) {
            USBS_CHECK(strcmp(usbs_status_string((usbs_status_t)i),
                              usbs_status_string((usbs_status_t)j)) != 0);
        }
    }

    /* Out-of-range values fall back rather than reading past the table. */
    USBS_CHECK_STR_EQ(usbs_status_string(USBS_STATUS_COUNT),
                      "USBS_ERR_UNKNOWN");
    USBS_CHECK_STR_EQ(usbs_status_string((usbs_status_t)9999),
                      "USBS_ERR_UNKNOWN");

    USBS_CHECK(usbs_ok(USBS_OK));
    USBS_CHECK(!usbs_ok(USBS_ERR_IO));
    USBS_CHECK(!usbs_ok(USBS_ERR_INVALID_ARG));

    return USBS_TEST_RESULT();
}
