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
    USBS_CHECK_STR_EQ(usbs_bus_type_string(USBS_BUS_NETWORK), "network");

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
 * Phase 17 (ARCHITECTURE.md section 23.3): an internal disk's serial names
 * the physical disk, which C:, D: and a recovery partition all share. Keying
 * a non-USB volume on it would merge those volumes' scan histories under
 * one identity. So a known non-USB bus always takes the volume key, and
 * never "usb:" or "serial:".
 */
static void test_identity_non_usb_volumes_key_on_volume(void)
{
    static const usbs_bus_type_t non_usb[] = {
        USBS_BUS_SATA, USBS_BUS_NVME, USBS_BUS_SCSI, USBS_BUS_SD,
        USBS_BUS_OTHER, USBS_BUS_NETWORK
    };
    char          buf[USBS_IDENTITY_MAX];
    char          other[USBS_IDENTITY_MAX];
    usbs_device_t device;
    size_t        i;

    for (i = 0; i < USBS_ARRAY_LEN(non_usb); ++i) {
        device = make_device("\\\\?\\Volume{cccc}\\", NULL, NULL, "NVME-SERIAL-01");
        device.bus_type = non_usb[i];
        USBS_CHECK(usbs_ok(usbs_device_identity(&device, buf, sizeof(buf))));
        USBS_CHECK_STR_EQ(buf, "volume:\\\\?\\Volume{cccc}\\");
    }

    /* Two volumes on one internal disk (same serial) stay distinct. */
    device = make_device("\\\\?\\Volume{cccc}\\", NULL, NULL, "NVME-SERIAL-01");
    device.bus_type = USBS_BUS_NVME;
    USBS_CHECK(usbs_ok(usbs_device_identity(&device, buf, sizeof(buf))));
    device = make_device("\\\\?\\Volume{dddd}\\", NULL, NULL, "NVME-SERIAL-01");
    device.bus_type = USBS_BUS_NVME;
    USBS_CHECK(usbs_ok(usbs_device_identity(&device, other, sizeof(other))));
    USBS_CHECK(strcmp(buf, other) != 0);

    /* A network share keys on its UNC volume path, never its drive letter. */
    device = make_device("\\\\?\\UNC\\fileserver\\team\\", NULL, NULL, NULL);
    device.bus_type = USBS_BUS_NETWORK;
    snprintf(device.mount_points[0], USBS_MOUNT_POINT_MAX, "Z:");
    device.mount_point_count = 1;
    USBS_CHECK(usbs_ok(usbs_device_identity(&device, buf, sizeof(buf))));
    USBS_CHECK_STR_EQ(buf, "volume:\\\\?\\UNC\\fileserver\\team\\");

    /* USB and unknown keep the pre-Phase-17 rules, so no existing report
     * store key changes. */
    device = make_device("\\\\?\\Volume{cccc}\\", NULL, NULL, "ABC123");
    device.bus_type = USBS_BUS_USB;
    USBS_CHECK(usbs_ok(usbs_device_identity(&device, buf, sizeof(buf))));
    USBS_CHECK_STR_EQ(buf, "serial:ABC123");
    device.bus_type = USBS_BUS_UNKNOWN;
    USBS_CHECK(usbs_ok(usbs_device_identity(&device, buf, sizeof(buf))));
    USBS_CHECK_STR_EQ(buf, "serial:ABC123");
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

/*
 * Phase 14 regression guard. USBS_IDENTITY_MAX is derived from
 * USBS_VOLUME_PATH_MAX precisely so the "volume:<path>" fallback - the last
 * resort, used whenever a device exposes neither USB ids nor a serial - can
 * never fail for lack of room. A POSIX mount path ("/media/alice/<label>")
 * is long enough to have broken this when volume_path grew from 64 to 512
 * against a literal 160, and the breakage would have shown up as a failed
 * scan rather than as anything pointing at this header.
 *
 * Asserting on a deliberately maximum-length path keeps the two constants
 * tied together: raise one without the other and this fails immediately, in
 * the right place.
 */
static void test_identity_fits_longest_volume_path(void)
{
    char          buf[USBS_IDENTITY_MAX];
    usbs_device_t device;
    char          longest[USBS_VOLUME_PATH_MAX];
    size_t        i;

    for (i = 0; i < sizeof(longest) - 1; ++i) {
        longest[i] = 'x';
    }
    longest[sizeof(longest) - 1] = '\0';

    device = make_device(longest, NULL, NULL, NULL);
    USBS_CHECK_STR_EQ(device.volume_path, longest);

    USBS_CHECK(usbs_ok(usbs_device_identity(&device, buf, sizeof(buf))));
    USBS_CHECK(strncmp(buf, "volume:", 7) == 0);
    USBS_CHECK_STR_EQ(buf + 7, longest);

    /* A realistic POSIX mount path, the case that actually motivated this. */
    device = make_device("/media/alice/SANDISK_ULTRA_64GB", NULL, NULL, NULL);
    USBS_CHECK(usbs_ok(usbs_device_identity(&device, buf, sizeof(buf))));
    USBS_CHECK_STR_EQ(buf, "volume:/media/alice/SANDISK_ULTRA_64GB");
}

/* Mount points must hold a path, not just a drive letter - a Windows folder
 * mount ("C:\Mounts\MyUSB") overflowed the old 8-byte field too, so this is a
 * current-platform guard as much as a POSIX one. */
static void test_mount_point_holds_a_full_path(void)
{
    usbs_device_t device = make_device("\\\\?\\Volume{aaaa}\\", NULL, NULL, NULL);
    const char   *folder_mount = "C:\\Mounts\\MyUSB";
    const char   *posix_mount  = "/media/alice/SANDISK_ULTRA_64GB";

    snprintf(device.mount_points[0], USBS_MOUNT_POINT_MAX, "%s", folder_mount);
    snprintf(device.mount_points[1], USBS_MOUNT_POINT_MAX, "%s", posix_mount);
    device.mount_point_count = 2;

    USBS_CHECK_STR_EQ(device.mount_points[0], folder_mount);
    USBS_CHECK_STR_EQ(device.mount_points[1], posix_mount);
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

/* Phase 17: the mode-aware predicate. USB_ONLY must be exactly the old
 * predicate; ALL_VOLUMES accepts any bus but still wants media and a place
 * the volume is actually mounted. */
static void test_scannable_by_mode(void)
{
    usbs_device_t internal = make_device("\\\\?\\Volume{aaaa}\\", NULL, NULL, "S");
    usbs_device_t usb      = make_device("\\\\?\\Volume{bbbb}\\", "0781", "5583", NULL);

    internal.bus_type      = USBS_BUS_NVME;
    internal.media_present = true;
    snprintf(internal.mount_points[0], USBS_MOUNT_POINT_MAX, "C:");
    internal.mount_point_count = 1;

    usb.bus_type      = USBS_BUS_USB;
    usb.media_present = true;
    snprintf(usb.mount_points[0], USBS_MOUNT_POINT_MAX, "E:");
    usb.mount_point_count = 1;

    /* The default mode never offers an internal drive. */
    USBS_CHECK(!usbs_device_is_scannable(&internal, USBS_ENUM_USB_ONLY));
    USBS_CHECK(usbs_device_is_scannable(&internal, USBS_ENUM_ALL_VOLUMES));

    /* A USB device is scannable in both. */
    USBS_CHECK(usbs_device_is_scannable(&usb, USBS_ENUM_USB_ONLY));
    USBS_CHECK(usbs_device_is_scannable(&usb, USBS_ENUM_ALL_VOLUMES));

    /* No media: not scannable in either mode. */
    internal.media_present = false;
    USBS_CHECK(!usbs_device_is_scannable(&internal, USBS_ENUM_ALL_VOLUMES));
    internal.media_present = true;

    /* No mount point (an EFI/recovery partition): not offered as a drive. */
    internal.mount_point_count = 0;
    USBS_CHECK(!usbs_device_is_scannable(&internal, USBS_ENUM_ALL_VOLUMES));

    USBS_CHECK(!usbs_device_is_scannable(NULL, USBS_ENUM_ALL_VOLUMES));
    USBS_CHECK(!usbs_device_is_scannable(NULL, USBS_ENUM_USB_ONLY));
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
    test_identity_non_usb_volumes_key_on_volume();
    test_identity_ignores_drive_letter();
    test_identity_errors();
    test_identity_fits_longest_volume_path();
    test_mount_point_holds_a_full_path();
    test_scannable_predicate();
    test_scannable_by_mode();
    test_list_growth();
    test_enumerate_through_seam();
    return USBS_TEST_RESULT();
}
