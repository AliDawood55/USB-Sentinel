#include <string.h>

#include "test_util.h"
#include "usbsentinel/env.h"

#define TEST_VAR "USBS_TEST_ENV_VAR_PHASE6"

static void test_roundtrip(void)
{
    char buf[64];

    USBS_CHECK(usbs_ok(usbs_setenv(TEST_VAR, "hello world")));
    USBS_CHECK(usbs_ok(usbs_getenv(TEST_VAR, buf, sizeof(buf))));
    USBS_CHECK_STR_EQ(buf, "hello world");

    USBS_CHECK(usbs_ok(usbs_setenv(TEST_VAR, "second value")));
    USBS_CHECK(usbs_ok(usbs_getenv(TEST_VAR, buf, sizeof(buf))));
    USBS_CHECK_STR_EQ(buf, "second value");
}

static void test_unset_and_empty_are_not_found(void)
{
    char buf[64];

    /* Clearing via NULL/"" must make a subsequent get report NOT_FOUND, not
     * an empty string - an accidentally-blank variable should never
     * silently resolve to an empty path. */
    USBS_CHECK(usbs_ok(usbs_setenv(TEST_VAR, "something")));
    USBS_CHECK(usbs_ok(usbs_setenv(TEST_VAR, NULL)));
    USBS_CHECK(usbs_getenv(TEST_VAR, buf, sizeof(buf)) == USBS_ERR_NOT_FOUND);

    USBS_CHECK(usbs_ok(usbs_setenv(TEST_VAR, "something")));
    USBS_CHECK(usbs_ok(usbs_setenv(TEST_VAR, "")));
    USBS_CHECK(usbs_getenv(TEST_VAR, buf, sizeof(buf)) == USBS_ERR_NOT_FOUND);
}

static void test_never_set_is_not_found(void)
{
    char buf[64];
    USBS_CHECK(usbs_getenv("USBS_TEST_ENV_VAR_NEVER_SET_PHASE6", buf, sizeof(buf)) ==
              USBS_ERR_NOT_FOUND);
}

static void test_buffer_too_small(void)
{
    char tiny[4];
    USBS_CHECK(usbs_ok(usbs_setenv(TEST_VAR, "way too long for a 4-byte buffer")));
    USBS_CHECK(usbs_getenv(TEST_VAR, tiny, sizeof(tiny)) == USBS_ERR_NO_MEMORY);
}

static void test_invalid_args(void)
{
    char buf[64];
    USBS_CHECK(usbs_getenv(NULL, buf, sizeof(buf)) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_getenv(TEST_VAR, NULL, sizeof(buf)) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_getenv(TEST_VAR, buf, 0) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_setenv(NULL, "x") == USBS_ERR_INVALID_ARG);
}

int main(void)
{
    test_roundtrip();
    test_unset_and_empty_are_not_found();
    test_never_set_is_not_found();
    test_buffer_too_small();
    test_invalid_args();

    usbs_setenv(TEST_VAR, NULL); /* leave the environment clean */
    return USBS_TEST_RESULT();
}
