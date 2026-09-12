#include <stdio.h>
#include <string.h>

#include "test_util.h"
#include "usbsentinel/log.h"

/* Opens a scratch file for read/write without tripping MSVC's C4996. */
static FILE *open_scratch(const char *path)
{
    FILE *f = NULL;
#if defined(_MSC_VER)
    if (fopen_s(&f, path, "w+") != 0) {
        f = NULL;
    }
#else
    f = fopen(path, "w+");
#endif
    return f;
}

static void test_levels(void)
{
    USBS_CHECK_STR_EQ(usbs_log_level_string(USBS_LOG_TRACE), "TRACE");
    USBS_CHECK_STR_EQ(usbs_log_level_string(USBS_LOG_DEBUG), "DEBUG");
    USBS_CHECK_STR_EQ(usbs_log_level_string(USBS_LOG_INFO),  "INFO");
    USBS_CHECK_STR_EQ(usbs_log_level_string(USBS_LOG_WARN),  "WARN");
    USBS_CHECK_STR_EQ(usbs_log_level_string(USBS_LOG_ERROR), "ERROR");

    usbs_log_set_level(USBS_LOG_WARN);
    USBS_CHECK(usbs_log_get_level() == USBS_LOG_WARN);

    /* At WARN, anything below WARN is suppressed. */
    USBS_CHECK(!usbs_log_enabled(USBS_LOG_TRACE));
    USBS_CHECK(!usbs_log_enabled(USBS_LOG_DEBUG));
    USBS_CHECK(!usbs_log_enabled(USBS_LOG_INFO));
    USBS_CHECK(usbs_log_enabled(USBS_LOG_WARN));
    USBS_CHECK(usbs_log_enabled(USBS_LOG_ERROR));

    /* OFF suppresses everything, including ERROR. */
    usbs_log_set_level(USBS_LOG_OFF);
    USBS_CHECK(!usbs_log_enabled(USBS_LOG_ERROR));
    USBS_CHECK(!usbs_log_enabled(USBS_LOG_TRACE));

    /* TRACE lets everything through. */
    usbs_log_set_level(USBS_LOG_TRACE);
    USBS_CHECK(usbs_log_enabled(USBS_LOG_TRACE));
    USBS_CHECK(usbs_log_enabled(USBS_LOG_ERROR));
}

static void test_output(void)
{
    const char *path = "usbs_log_test.tmp";
    FILE       *scratch = open_scratch(path);
    char        buf[512];
    size_t      n;

    USBS_CHECK(scratch != NULL);
    if (scratch == NULL) {
        return;
    }

    usbs_log_set_stream(scratch);
    usbs_log_set_level(USBS_LOG_INFO);

    usbs_log_write(USBS_LOG_DEBUG, "suppressed-%d", 1);  /* below threshold */
    usbs_log_write(USBS_LOG_ERROR, "emitted-%s", "one");

    rewind(scratch);
    n = fread(buf, 1, sizeof(buf) - 1, scratch);
    buf[n] = '\0';

    USBS_CHECK(strstr(buf, "suppressed-1") == NULL);
    USBS_CHECK(strstr(buf, "emitted-one") != NULL);
    USBS_CHECK(strstr(buf, "ERROR") != NULL);

    /* Restore the default sink before the stream is closed. */
    usbs_log_set_stream(NULL);
    fclose(scratch);
    remove(path);
}

int main(void)
{
    test_levels();
    test_output();
    return USBS_TEST_RESULT();
}
