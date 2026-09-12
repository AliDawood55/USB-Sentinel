/*
 * Tests for `scan`'s path-target fallback (ARCHITECTURE.md section 20.11):
 * usbs_cli_build_path_device(), an internal surface of cmd_scan.c exposed
 * non-static purely so this file can exercise it - the same pattern
 * hash_match.c uses for usbs_hash_match_lookup() (see that file's own
 * comment). Full usbs_cli_cmd_scan() is not run here: it calls
 * usbs_store_open(), which resolves the real per-user data directory, and a
 * test must not touch that.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "test_util.h"
#include "usbsentinel/device.h"
#include "usbsentinel/path.h"
#include "usbsentinel/platform.h"

extern usbs_status_t usbs_cli_build_path_device(const char *path, usbs_device_t *out_device);

static void make_scratch_root(char *out, size_t cap)
{
    static usbs_bool seeded = false;
    if (!seeded) {
        srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)out);
        seeded = true;
    }
    snprintf(out, cap, "test_cmd_scan_scratch_%08x", (unsigned)rand());
}

/* A valid, existing directory without a trailing separator must succeed and
 * gain exactly one. */
static void test_path_without_trailing_separator(void)
{
    char          root[260];
    usbs_device_t device;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    USBS_CHECK(!usbs_path_is_separator(root[strlen(root) - 1]));

    USBS_CHECK(usbs_ok(usbs_cli_build_path_device(root, &device)));
    USBS_CHECK(usbs_path_is_separator(device.volume_path[strlen(device.volume_path) - 1]));
    USBS_CHECK(strncmp(device.volume_path, root, strlen(root)) == 0);
    USBS_CHECK(strlen(device.volume_path) == strlen(root) + 1);
}

/* A path that already ends in a separator must not gain a second one - the
 * whole point of reusing usbs_path_join() rather than always appending. */
static void test_path_with_trailing_separator_not_doubled(void)
{
    char          root[260];
    char          with_sep[262];
    usbs_device_t device;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    snprintf(with_sep, sizeof(with_sep), "%s%s", root, USBS_PATH_SEP);

    USBS_CHECK(usbs_ok(usbs_cli_build_path_device(with_sep, &device)));
    USBS_CHECK_STR_EQ(device.volume_path, with_sep);
}

/*
 * Honesty over inference (this is the whole point of the function): nothing
 * about bus type, vendor, serial or capacity was actually queried, so none
 * of it may be reported as known.
 */
static void test_path_device_fields_are_honest(void)
{
    char          root[260];
    usbs_device_t device;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));

    USBS_CHECK(usbs_ok(usbs_cli_build_path_device(root, &device)));
    USBS_CHECK(device.bus_type == USBS_BUS_UNKNOWN);
    USBS_CHECK(device.media_present == true);
    USBS_CHECK(device.vendor[0] == '\0');
    USBS_CHECK(device.product[0] == '\0');
    USBS_CHECK(device.serial[0] == '\0');
    USBS_CHECK(device.usb_vid[0] == '\0');
    USBS_CHECK(device.usb_pid[0] == '\0');
    USBS_CHECK(device.capacity_bytes == 0);
    USBS_CHECK(device.free_bytes == 0);

    /* Not itself a USB device by this function's own honest bookkeeping -
     * callers that gate on usbs_device_is_scannable_usb() must not treat a
     * path target as one. */
    USBS_CHECK(!usbs_device_is_scannable_usb(&device));

    /* With no USB ids and no serial, identity falls back to "volume:<path>" -
     * see device.c's usbs_device_identity() and this file's header comment. */
    {
        char identity[USBS_IDENTITY_MAX];
        USBS_CHECK(usbs_ok(usbs_device_identity(&device, identity, sizeof(identity))));
        USBS_CHECK(strncmp(identity, "volume:", 7) == 0);
        USBS_CHECK(strstr(identity, root) != NULL);
    }

    /* mount_points[0] is decorative display only, not part of the identity
     * key, but should still read back the path the caller gave. */
    USBS_CHECK(device.mount_point_count == 1);
    USBS_CHECK_STR_EQ(device.mount_points[0], root);
}

/* A path that does not exist must be rejected, not silently accepted -
 * scanner.c should never be handed a volume_path that cannot be opened. */
static void test_nonexistent_path_rejected(void)
{
    usbs_device_t device;
    USBS_CHECK(usbs_cli_build_path_device(
        "test_cmd_scan_does_not_exist_anywhere", &device) == USBS_ERR_NOT_FOUND);
}

/* A plain file (not a directory) must also be rejected: opendir()/
 * FindFirstFileW("...\*") both fail on one, and a detector's traversal
 * assumes volume_path names a directory. */
static void test_regular_file_rejected(void)
{
    char          root[260];
    char          file_path[300];
    usbs_device_t device;

    make_scratch_root(root, sizeof(root));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    USBS_CHECK(usbs_ok(usbs_path_join(file_path, sizeof(file_path), root, "not_a_dir.txt")));
    USBS_CHECK(usbs_ok(usbs_platform_write_file(file_path, "x", 1)));

    USBS_CHECK(!usbs_ok(usbs_cli_build_path_device(file_path, &device)));
}

static void test_invalid_args(void)
{
    usbs_device_t device;
    USBS_CHECK(usbs_cli_build_path_device(NULL, &device) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_cli_build_path_device("x", NULL) == USBS_ERR_INVALID_ARG);
}

/* A path too long for volume_path must be reported, not truncated into a
 * shorter path that silently names something else. */
static void test_path_too_long_reported(void)
{
    char          huge[USBS_VOLUME_PATH_MAX + 64];
    usbs_device_t device;
    size_t        i;

    huge[0] = '.';
#if defined(_WIN32)
    huge[1] = '\\';
#else
    huge[1] = '/';
#endif
    for (i = 2; i < sizeof(huge) - 1; ++i) {
        huge[i] = 'x';
    }
    huge[sizeof(huge) - 1] = '\0';

    USBS_CHECK(usbs_cli_build_path_device(huge, &device) == USBS_ERR_NO_MEMORY);
}

int main(void)
{
    test_path_without_trailing_separator();
    test_path_with_trailing_separator_not_doubled();
    test_path_device_fields_are_honest();
    test_nonexistent_path_rejected();
    test_regular_file_rejected();
    test_invalid_args();
    test_path_too_long_reported();
    return USBS_TEST_RESULT();
}
