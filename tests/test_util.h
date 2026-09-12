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
