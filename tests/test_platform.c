/*
 * Platform-layer tests against the live Win32 source.
 *
 * These must pass on a machine with NO USB device attached, and must pass
 * unelevated. They therefore assert invariants and self-consistency rather
 * than the presence of any particular hardware.
 */
#include <string.h>

#include "test_util.h"
#include "usbsentinel/platform.h"

static void test_win32_status_translation(void)
{
    /* 0 is ERROR_SUCCESS; 5 ACCESS_DENIED; 2 FILE_NOT_FOUND; 21 NOT_READY. */
    USBS_CHECK(usbs_platform_status_from_win32(0) == USBS_OK);
#if defined(_WIN32)
    USBS_CHECK(usbs_platform_status_from_win32(5) == USBS_ERR_ACCESS_DENIED);
    USBS_CHECK(usbs_platform_status_from_win32(2) == USBS_ERR_NOT_FOUND);
    USBS_CHECK(usbs_platform_status_from_win32(21) == USBS_ERR_IO);

    /* An unmapped code must not be reported as success. */
    USBS_CHECK(usbs_platform_status_from_win32(0x0FFFFFFF) != USBS_OK);
#endif
}

static void test_capabilities_init(void)
{
    usbs_capabilities_t caps;

    memset(&caps, 0xFF, sizeof(caps));
    usbs_capabilities_init(&caps);
    USBS_CHECK(caps.can_read_raw_volume == false);
    USBS_CHECK(caps.can_read_physical_disk == false);

    usbs_capabilities_init(NULL); /* must not crash */
}

static void test_probe_rejects_null(void)
{
    usbs_device_t       device;
    usbs_capabilities_t caps;

    usbs_device_init(&device);
    USBS_CHECK(usbs_platform_probe_capabilities(NULL, &caps) ==
               USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_platform_probe_capabilities(&device, NULL) ==
               USBS_ERR_INVALID_ARG);
}

/*
 * Live enumeration. Zero devices is a valid outcome; what must hold is that
 * the call succeeds and every record it produces is internally consistent.
 */
static void test_live_enumeration(void)
{
    usbs_device_source_t source = usbs_platform_device_source();
    usbs_device_list_t   list;
    usbs_status_t        status;
    size_t               i;

    status = usbs_device_enumerate(&source, &list);

#if !defined(_WIN32)
    /* No POSIX enumeration backend until Phase 14b, so the source's
     * `enumerate` is NULL and the seam must report that rather than pretend
     * to have found nothing. The loop counter below is Windows-only. */
    USBS_UNUSED(i);
    USBS_CHECK(status == USBS_ERR_UNSUPPORTED);
    return;
#else
    USBS_CHECK(usbs_ok(status));
    if (!usbs_ok(status)) {
        return;
    }

    for (i = 0; i < list.count; ++i) {
        const usbs_device_t *device = &list.items[i];
        char                 identity[USBS_IDENTITY_MAX];
        usbs_capabilities_t  caps;

        /* Every volume must carry a volume path; that is the scan root. */
        USBS_CHECK(device->volume_path[0] != '\0');
        USBS_CHECK(strncmp(device->volume_path, "\\\\?\\Volume", 10) == 0);

        USBS_CHECK(device->mount_point_count <= USBS_MOUNT_POINTS_MAX);

        /* Identity must always resolve, even with no serial and no VID/PID. */
        USBS_CHECK(usbs_ok(
            usbs_device_identity(device, identity, sizeof(identity))));
        USBS_CHECK(identity[0] != '\0');

        /* Free space can never exceed capacity. */
        USBS_CHECK(device->free_bytes <= device->capacity_bytes);

        /* Absent media implies no reported capacity. */
        if (!device->media_present) {
            USBS_CHECK(device->capacity_bytes == 0);
        }

        /* USB ids come in pairs or not at all. */
        USBS_CHECK((device->usb_vid[0] == '\0') ==
                   (device->usb_pid[0] == '\0'));

        /* Probing must never fail outright, elevated or not. */
        USBS_CHECK(usbs_ok(usbs_platform_probe_capabilities(device, &caps)));
    }

    usbs_device_list_free(&list);
#endif
}

/* Enumeration must be repeatable and stable across back-to-back calls. */
static void test_enumeration_is_repeatable(void)
{
#if defined(_WIN32)
    usbs_device_source_t source = usbs_platform_device_source();
    usbs_device_list_t   first;
    usbs_device_list_t   second;

    if (!usbs_ok(usbs_device_enumerate(&source, &first))) {
        return;
    }
    if (!usbs_ok(usbs_device_enumerate(&source, &second))) {
        usbs_device_list_free(&first);
        return;
    }

    USBS_CHECK(first.count == second.count);

    usbs_device_list_free(&first);
    usbs_device_list_free(&second);
#endif
}

int main(void)
{
    test_win32_status_translation();
    test_capabilities_init();
    test_probe_rejects_null();
    test_live_enumeration();
    test_enumeration_is_repeatable();
    return USBS_TEST_RESULT();
}
