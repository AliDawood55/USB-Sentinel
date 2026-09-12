/*
 * Device model tests. These exercise the portable half of the platform module
 * through a fixture source, so they pass with no USB hardware attached.
 */
#include <string.h>

#include "test_util.h"
#include "usbsentinel/device.h"

/* --- fixture source --- */

typedef struct fixture {
    const usbs_device_t *items;
    size_t               count;
    usbs_status_t        forced_status;
} fixture_t;

static usbs_status_t fixture_enumerate(void *ctx, usbs_device_list_t *out)
{
    fixture_t *fx = (fixture_t *)ctx;
    size_t     i;

    if (fx->forced_status != USBS_OK) {
        return fx->forced_status;
    }
    for (i = 0; i < fx->count; ++i) {
        usbs_status_t status = usbs_device_list_push(out, &fx->items[i]);
        if (!usbs_ok(status)) {
            return status;
        }
    }
    return USBS_OK;
}

static usbs_device_t make_device(const char *volume, const char *vid,
                                 const char *pid, const char *serial)
{
    usbs_device_t device;

    usbs_device_init(&device);
    snprintf(device.volume_path, sizeof(device.volume_path), "%s", volume);
    if (vid != NULL) {
        snprintf(device.usb_vid, sizeof(device.usb_vid), "%s", vid);
    }
    if (pid != NULL) {
        snprintf(device.usb_pid, sizeof(device.usb_pid), "%s", pid);
    }
    if (serial != NULL) {
        snprintf(device.serial, sizeof(device.serial), "%s", serial);
    }
    return device;
}

/* --- tests --- */

static void test_init_zeroes(void)
{
    usbs_device_t device;

    memset(&device, 0xAB, sizeof(device));
    usbs_device_init(&device);

    USBS_CHECK(device.volume_path[0] == '\0');
    USBS_CHECK(device.mount_point_count == 0);
    USBS_CHECK(device.bus_type == USBS_BUS_UNKNOWN);
    USBS_CHECK(device.has_disk_number == false);
    USBS_CHECK(device.media_present == false);
    USBS_CHECK(device.capacity_bytes == 0);

    /* A NULL argument must not crash. */
    usbs_device_init(NULL);
}

static void test_bus_type_strings(void)
{
    USBS_CHECK_STR_EQ(usbs_bus_type_string(USBS_BUS_USB), "USB");
    USBS_CHECK_STR_EQ(usbs_bus_type_string(USBS_BUS_SATA), "SATA");
    USBS_CHECK_STR_EQ(usbs_bus_type_string(USBS_BUS_NVME), "NVMe");
    USBS_CHECK_STR_EQ(usbs_bus_type_string(USBS_BUS_SD), "SD");
    USBS_CHECK_STR_EQ(usbs_bus_type_string(USBS_BUS_UNKNOWN), "unknown");

    /* Out-of-range must fall back rather than read past the table. */
    USBS_CHECK_STR_EQ(usbs_bus_type_string((usbs_bus_type_t)9999), "unknown");
}

/* Identity is the storage key, so its precedence order is load-bearing. */
static void test_identity_precedence(void)
{
    char          buf[USBS_IDENTITY_MAX];
    usbs_device_t device;

    device = make_device("\\\\?\\Volume{aaaa}\\", "0781", "5583", "ABC123");
    USBS_CHECK(usbs_ok(usbs_device_identity(&device, buf, sizeof(buf))));
    USBS_CHECK_STR_EQ(buf, "usb:0781-5583:ABC123");

    device = make_device("\\\\?\\Volume{aaaa}\\", "0781", "5583", NULL);
    USBS_CHECK(usbs_ok(usbs_device_identity(&device, buf, sizeof(buf))));
    USBS_CHECK_STR_EQ(buf, "usb:0781-5583");

    device = make_device("\\\\?\\Volume{aaaa}\\", NULL, NULL, "ABC123");
    USBS_CHECK(usbs_ok(usbs_device_identity(&device, buf, sizeof(buf))));
    USBS_CHECK_STR_EQ(buf, "serial:ABC123");

    device = make_device("\\\\?\\Volume{aaaa}\\", NULL, NULL, NULL);
    USBS_CHECK(usbs_ok(usbs_device_identity(&device, buf, sizeof(buf))));
    USBS_CHECK_STR_EQ(buf, "volume:\\\\?\\Volume{aaaa}\\");
}

/*
 * The whole point of the identity key is surviving drive-letter churn
 * (ARCHITECTURE.md section 7.2), so assert the letter never leaks into it.
 */
static void test_identity_ignores_drive_letter(void)
{
    char          before[USBS_IDENTITY_MAX];
    char          after[USBS_IDENTITY_MAX];
    usbs_device_t device;

    device = make_device("\\\\?\\Volume{aaaa}\\", "0781", "5583", "ABC123");

    snprintf(device.mount_points[0], USBS_MOUNT_POINT_MAX, "E:");
    device.mount_point_count = 1;
    USBS_CHECK(usbs_ok(usbs_device_identity(&device, before, sizeof(before))));

    snprintf(device.mount_points[0], USBS_MOUNT_POINT_MAX, "Z:");
    USBS_CHECK(usbs_ok(usbs_device_identity(&device, after, sizeof(after))));

    USBS_CHECK_STR_EQ(before, after);
    USBS_CHECK(strstr(before, "E:") == NULL);
    USBS_CHECK(strstr(before, "Z:") == NULL);
}

static void test_identity_errors(void)
{
    char          buf[USBS_IDENTITY_MAX];
    char          tiny[4];
    usbs_device_t device = make_device("\\\\?\\Volume{aaaa}\\", "0781", "5583",
                                       "ABC123");

    USBS_CHECK(usbs_device_identity(NULL, buf, sizeof(buf)) ==
               USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_device_identity(&device, NULL, sizeof(buf)) ==
               USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_device_identity(&device, buf, 0) == USBS_ERR_INVALID_ARG);

    /* Truncation must be reported, not silently accepted. */
    USBS_CHECK(usbs_device_identity(&device, tiny, sizeof(tiny)) ==
               USBS_ERR_NO_MEMORY);
}

static void test_scannable_predicate(void)
{
    usbs_device_t device = make_device("\\\\?\\Volume{aaaa}\\", NULL, NULL, NULL);

    device.bus_type      = USBS_BUS_USB;
    device.media_present = true;
    USBS_CHECK(usbs_device_is_scannable_usb(&device));

    device.media_present = false;
    USBS_CHECK(!usbs_device_is_scannable_usb(&device));

    device.media_present = true;
    device.bus_type      = USBS_BUS_SATA;
    USBS_CHECK(!usbs_device_is_scannable_usb(&device));

    USBS_CHECK(!usbs_device_is_scannable_usb(NULL));
}

static void test_list_growth(void)
{
    usbs_device_list_t list;
    usbs_device_t      device = make_device("\\\\?\\Volume{aaaa}\\", NULL, NULL,
                                            NULL);
    int                i;

    usbs_device_list_init(&list);
    USBS_CHECK(list.count == 0);
    USBS_CHECK(list.items == NULL);

    /* Push past the initial capacity of 8 to exercise the realloc path. */
    for (i = 0; i < 50; ++i) {
        USBS_CHECK(usbs_ok(usbs_device_list_push(&list, &device)));
    }
    USBS_CHECK(list.count == 50);
    USBS_CHECK(list.capacity >= 50);
    USBS_CHECK_STR_EQ(list.items[49].volume_path, "\\\\?\\Volume{aaaa}\\");

    usbs_device_list_free(&list);
    USBS_CHECK(list.count == 0);
    USBS_CHECK(list.items == NULL);

    /* Free must be idempotent and NULL-safe. */
    usbs_device_list_free(&list);
    usbs_device_list_free(NULL);

    USBS_CHECK(usbs_device_list_push(NULL, &device) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_device_list_push(&list, NULL) == USBS_ERR_INVALID_ARG);
}

static void test_enumerate_through_seam(void)
{
    usbs_device_t devices[2];
    fixture_t     fx;
    usbs_device_source_t source;
    usbs_device_list_t   list;

    devices[0] = make_device("\\\\?\\Volume{aaaa}\\", "0781", "5583", "AAA");
    devices[1] = make_device("\\\\?\\Volume{bbbb}\\", NULL, NULL, NULL);

    fx.items         = devices;
    fx.count         = 2;
    fx.forced_status = USBS_OK;

    source.enumerate = fixture_enumerate;
    source.ctx       = &fx;

    USBS_CHECK(usbs_ok(usbs_device_enumerate(&source, &list)));
    USBS_CHECK(list.count == 2);
    USBS_CHECK_STR_EQ(list.items[0].usb_vid, "0781");
    usbs_device_list_free(&list);

    /* A failing source must leave no allocation behind. */
    fx.forced_status = USBS_ERR_IO;
    USBS_CHECK(usbs_device_enumerate(&source, &list) == USBS_ERR_IO);
    USBS_CHECK(list.items == NULL);
    USBS_CHECK(list.count == 0);

    /* A source with no enumerate function is unsupported, not a crash. */
    source.enumerate = NULL;
    USBS_CHECK(usbs_device_enumerate(&source, &list) == USBS_ERR_UNSUPPORTED);

    USBS_CHECK(usbs_device_enumerate(NULL, &list) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_device_enumerate(&source, NULL) == USBS_ERR_INVALID_ARG);
}

int main(void)
{
    test_init_zeroes();
    test_bus_type_strings();
    test_identity_precedence();
    test_identity_ignores_drive_letter();
    test_identity_errors();
    test_scannable_predicate();
    test_list_growth();
    test_enumerate_through_seam();
    return USBS_TEST_RESULT();
}
