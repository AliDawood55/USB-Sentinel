/*
 * USB Sentinel - minimal test harness.
 *
 * No external dependency by design. Each test file defines checks with
 * USBS_CHECK and ends with USBS_TEST_RESULT(), which returns a process exit
 * code CTest can interpret.
 */
#ifndef USBSENTINEL_TEST_UTIL_H
#define USBSENTINEL_TEST_UTIL_H

#include <stdio.h>

static int usbs_test_failures = 0;
static int usbs_test_checks   = 0;

#define USBS_CHECK(cond)                                                      \
    do {                                                                      \
        ++usbs_test_checks;                                                   \
        if (!(cond)) {                                                        \
            ++usbs_test_failures;                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
        }                                                                     \
    } while (0)

/*
 * Like USBS_CHECK, but abandons the current test function when it fails.
 *
 * For checks that guard a dereference: `USBS_CHECK(count == 1)` followed by
 * `items[0].message` is a segfault when the count is really 0, and a
 * segfault takes down the whole executable, so CTest reports one crashed
 * binary instead of one failed assertion plus the results of every later
 * test in the file. That turns a small regression into a blind spot, which
 * is exactly when the remaining tests are most worth seeing.
 *
 * Only usable in a void function, which every test here is.
 */
#define USBS_REQUIRE(cond)                                                    \
    do {                                                                      \
        ++usbs_test_checks;                                                   \
        if (!(cond)) {                                                        \
            ++usbs_test_failures;                                             \
            fprintf(stderr, "FAIL %s:%d: %s (abandoning test)\n",             \
                    __FILE__, __LINE__, #cond);                               \
            return;                                                           \
        }                                                                     \
    } while (0)

#define USBS_CHECK_STR_EQ(a, b)                                               \
    do {                                                                      \
        const char *usbs_a_ = (a);                                            \
        const char *usbs_b_ = (b);                                            \
        ++usbs_test_checks;                                                   \
        if (usbs_a_ == NULL || usbs_b_ == NULL ||                             \
            strcmp(usbs_a_, usbs_b_) != 0) {                                  \
            ++usbs_test_failures;                                             \
            fprintf(stderr, "FAIL %s:%d: \"%s\" != \"%s\"\n",                 \
                    __FILE__, __LINE__,                                       \
                    usbs_a_ ? usbs_a_ : "(null)",                             \
                    usbs_b_ ? usbs_b_ : "(null)");                            \
        }                                                                     \
    } while (0)

#define USBS_TEST_RESULT()                                                    \
    (printf("%d checks, %d failure(s)\n", usbs_test_checks,                   \
            usbs_test_failures),                                              \
     usbs_test_failures == 0 ? 0 : 1)

#endif /* USBSENTINEL_TEST_UTIL_H */
