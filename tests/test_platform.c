/*
 * Platform-layer tests against the live Win32 source.
 *
 * These must pass on a machine with NO USB device attached, and must pass
 * unelevated. They therefore assert invariants and self-consistency rather
 * than the presence of any particular hardware.
 */
#include <string.h>

#include "test_util.h"
#include "usbsentinel/env.h"
#include "usbsentinel/path.h"
#include "usbsentinel/platform.h"

static void test_win32_status_translation(void)
{
#if defined(_WIN32)
    /* 0 is ERROR_SUCCESS; 5 ACCESS_DENIED; 2 FILE_NOT_FOUND; 21 NOT_READY. */
    USBS_CHECK(usbs_platform_status_from_win32(0) == USBS_OK);
    USBS_CHECK(usbs_platform_status_from_win32(5) == USBS_ERR_ACCESS_DENIED);
    USBS_CHECK(usbs_platform_status_from_win32(2) == USBS_ERR_NOT_FOUND);
    USBS_CHECK(usbs_platform_status_from_win32(21) == USBS_ERR_IO);

    /* An unmapped code must not be reported as success. */
    USBS_CHECK(usbs_platform_status_from_win32(0x0FFFFFFF) != USBS_OK);
#else
    /* There is no errno that corresponds to a Win32 error code, so the POSIX
     * backend reports the translation itself as unsupported rather than
     * inventing a mapping - including for 0, which must NOT come back as
     * USBS_OK and be mistaken for a successful translation. */
    USBS_CHECK(usbs_platform_status_from_win32(0) == USBS_ERR_UNSUPPORTED);
    USBS_CHECK(usbs_platform_status_from_win32(5) == USBS_ERR_UNSUPPORTED);
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
 *
 * Four genuinely different platform states (ARCHITECTURE.md section 21),
 * not two: Windows and Linux have full real enumeration (Linux's own
 * history moved through an intermediate, honestly-incomplete 14b.1 state
 * before 14b.2 completed it - see that branch's own comment); macOS has a
 * real backend too, implemented in a single commit (14b.3) rather than
 * two, so its invariants are the complete contract from the start, not an
 * intermediate one; any other POSIX still reports USBS_ERR_UNSUPPORTED.
 * Each branch asserts what is actually true for that state, not a lowest
 * common denominator - a test that only checked "does not crash" would
 * not have caught the qsort(NULL, 0, ...) class of bug this project
 * already found by being specific (ARCHITECTURE.md section 20.8), and
 * would not have caught THIS test itself missing a macOS branch entirely
 * and silently falling into the "unsupported" case below, which is
 * exactly what happened until this fix (section 21.3's macOS commit
 * shipped without updating this file, and macos-clang's Test step failed
 * as a direct result - found by CI, the same "let CI prove it" discipline
 * this whole file already follows for the other two backends, applied
 * here to this file's own coverage of a third).
 */
static void test_live_enumeration(void)
{
    usbs_device_source_t source = usbs_platform_device_source();
    usbs_device_list_t   list;
    usbs_status_t        status;
    size_t               i;

    status = usbs_device_enumerate(&source, &list);

#if defined(_WIN32)
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

#elif defined(__linux__)
    /*
     * This runs against the REAL /sys and /proc/self/mountinfo of whatever
     * machine executes the test - a CI runner's own root/boot disks, not a
     * fixture - so it is real integration coverage of the sysfs/mountinfo-
     * parsing algorithm, not a fixed-input unit test.
     * tests/test_device_linux.c covers the algorithm deterministically
     * against a fake tree instead; this test is what catches a defect that
     * only shows up against a real, messy, unpredictable disk and mount
     * layout - which it has already done once (ARCHITECTURE.md section
     * 21.2): a for-loop bug that silently broke every mountinfo match, and
     * a real container mount table whose bind-mounts land on plain files
     * rather than directories, both found by running this exact test
     * against a real, if unusual, environment rather than by inspection.
     *
     * As of 14b.2 every field is implemented, so the invariants below are
     * the real, complete contract - not "matches this step's known
     * incompleteness" the way 14b.1's version of this test was.
     */
    USBS_CHECK(usbs_ok(status));
    if (!usbs_ok(status)) {
        return;
    }

    for (i = 0; i < list.count; ++i) {
        const usbs_device_t *device = &list.items[i];
        char                 identity[USBS_IDENTITY_MAX];
        usbs_capabilities_t  caps;

        USBS_CHECK(device->mount_point_count <= USBS_MOUNT_POINTS_MAX);
        USBS_CHECK(device->free_bytes <= device->capacity_bytes);

        /* USB ids come in pairs or not at all - true regardless of
         * bus_type, the same invariant the Windows branch above asserts. */
        USBS_CHECK((device->usb_vid[0] == '\0') == (device->usb_pid[0] == '\0'));

        /* volume_path, when set, must be one of the mount_points this same
         * pass just found - it is chosen FROM that set (the first entry
         * that is verifiably a directory - device_linux.c's own comment on
         * why a mountinfo match is not automatically walkable: a
         * container's bind-mounts onto plain files are a real case this
         * test found, not a hypothetical one), never invented separately. */
        if (device->volume_path[0] != '\0') {
            usbs_u32  j;
            usbs_bool matches_a_mount_point = false;
            size_t    len = strlen(device->volume_path);

            USBS_CHECK(len > 0 && usbs_path_is_separator(device->volume_path[len - 1]));
            for (j = 0; j < device->mount_point_count; ++j) {
                size_t mp_len = strlen(device->mount_points[j]);
                if (mp_len > 0 && mp_len <= len &&
                    strncmp(device->volume_path, device->mount_points[j], mp_len) == 0) {
                    matches_a_mount_point = true;
                    break;
                }
            }
            USBS_CHECK(matches_a_mount_point);
        }

        /* Deliberately no "USB implies real hardware fields present" or
         * "not USB implies unknown vendor" assertion here: the ancestor
         * walk's positive path (a genuine USB device, with real
         * idVendor/idProduct/serial) cannot be exercised in CI at all -
         * there is no removable USB hardware attached to a CI runner - and
         * is instead verified via real hardware through the Phase 14b.4
         * beta-tester process (ARCHITECTURE.md section 21.4). Asserting
         * something here that only a real USB device could satisfy would
         * either never run (vacuously true, worthless) or, worse, could be
         * quietly wrong and nobody would notice for years.
         */

        /* Identity must always resolve, even with no serial and no VID/PID
         * and no volume_path - the "volume:<possibly empty>" fallback. */
        USBS_CHECK(usbs_ok(
            usbs_device_identity(device, identity, sizeof(identity))));
        USBS_CHECK(identity[0] != '\0');

        /* Capability probing is deliberately deferred for all of Phase 14b
         * (this file's own header comment); UNSUPPORTED is the correct,
         * documented answer here, not a failure to tolerate. */
        USBS_CHECK(usbs_platform_probe_capabilities(device, &caps) ==
                   USBS_ERR_UNSUPPORTED);
    }

    usbs_device_list_free(&list);

#elif defined(__APPLE__)
    /*
     * Runs against whatever real disks and mounted volumes this machine
     * (a CI runner, or a real Mac) actually has - the same "real
     * environment, not a fixture" coverage the Linux branch above
     * provides, and the ONLY verification device_macos.c gets at all
     * before real hardware: there is no removable USB device attached to
     * a CI runner, so this cannot exercise the ancestor walk's positive
     * path, but it does exercise the full DiskArbitration-derived
     * enumeration end to end (real mount points, real filesystem types,
     * real capacities) against whatever internal/virtual disks are
     * actually present.
     *
     * Unlike Linux's 14b.1/14b.2 split, device_macos.c implemented every
     * field in one commit, so these invariants are the complete contract,
     * not an intermediate one - and unlike Linux, bus_type is not
     * restricted to "USB or UNKNOWN": DeviceProtocol already resolves the
     * full SATA/NVMe/SCSI/SD set (ARCHITECTURE.md section 21.3), so no
     * assertion here should assume UNKNOWN is the only non-USB outcome.
     */
    USBS_CHECK(usbs_ok(status));
    if (!usbs_ok(status)) {
        return;
    }

    for (i = 0; i < list.count; ++i) {
        const usbs_device_t *device = &list.items[i];
        char                 identity[USBS_IDENTITY_MAX];
        usbs_capabilities_t  caps;

        USBS_CHECK(device->mount_point_count <= USBS_MOUNT_POINTS_MAX);
        USBS_CHECK(device->free_bytes <= device->capacity_bytes);
        USBS_CHECK((device->usb_vid[0] == '\0') == (device->usb_pid[0] == '\0'));

        /* volume_path, when set, carries the device.h-mandated trailing
         * separator and must be mounted (media_present true) - unlike
         * Linux's mountinfo, which can enumerate multiple mount points
         * for one device (including ones that are not the volume's own
         * root, such as a container's file bind-mounts), DiskArbitration
         * reports exactly the volume's own mount point or nothing, so
         * there is no equivalent "must match one of several candidates"
         * check to make here. */
        if (device->volume_path[0] != '\0') {
            size_t len = strlen(device->volume_path);
            USBS_CHECK(len > 0 && usbs_path_is_separator(device->volume_path[len - 1]));
            USBS_CHECK(device->media_present == true);
        }

        /* Deliberately no assertion tying bus_type to any particular
         * hardware fact: the ancestor walk's positive USB path cannot be
         * exercised without a real USB device, which no CI runner has -
         * verified instead via ARCHITECTURE.md section 21.4's beta-tester
         * process. Asserting something here that only real hardware could
         * satisfy would either never run (vacuously true) or be quietly
         * wrong for years without anyone noticing, the same reasoning the
         * Linux branch above already gives. */

        USBS_CHECK(usbs_ok(
            usbs_device_identity(device, identity, sizeof(identity))));
        USBS_CHECK(identity[0] != '\0');

        /* Capability probing is deliberately deferred for all of Phase 14b,
         * on every platform (this file's own header comment). */
        USBS_CHECK(usbs_platform_probe_capabilities(device, &caps) ==
                   USBS_ERR_UNSUPPORTED);
    }

    usbs_device_list_free(&list);

#else
    /* No enumeration backend yet on this POSIX host (any UNIX other than
     * Linux/macOS; ARCHITECTURE.md section 21) - the seam reports that
     * honestly rather than pretending to have found nothing. */
    USBS_UNUSED(i);
    USBS_CHECK(status == USBS_ERR_UNSUPPORTED);
#endif
}

/*
 * Phase 17 (ARCHITECTURE.md section 23.1): USBS_ENUM_ALL_VOLUMES against the
 * real machine.
 *
 * Every Windows host that can run this test boots from an internal volume
 * mounted at %SystemDrive%, CI runners included. So unlike the USB positive
 * path, the all-volumes positive path is checkable here: the system drive
 * must be enumerated, must be scannable in ALL_VOLUMES mode, and (not
 * being USB) must NOT be offered in the default mode. On POSIX the mode is
 * a no-op by contract (platform.h), which is checked directly.
 */
static void test_all_volumes_enumeration(void)
{
#if defined(_WIN32)
    usbs_device_source_t usb_source = usbs_platform_device_source_ex(USBS_ENUM_USB_ONLY);
    usbs_device_source_t all_source = usbs_platform_device_source_ex(USBS_ENUM_ALL_VOLUMES);
    usbs_device_list_t   usb_list;
    usbs_device_list_t   all_list;
    char                 system_drive[16]; /* "C:" */
    usbs_bool            found_system_drive = false;
    size_t               i;

    USBS_CHECK(usbs_ok(usbs_getenv("SystemDrive", system_drive, sizeof(system_drive))));
    USBS_CHECK(system_drive[0] != '\0');
    USBS_CHECK(usbs_ok(usbs_device_enumerate(&usb_source, &usb_list)));
    USBS_CHECK(usbs_ok(usbs_device_enumerate(&all_source, &all_list)));

    /* ALL_VOLUMES only ever adds (network drives); it never loses a local
     * volume the default mode reports. */
    USBS_CHECK(all_list.count >= usb_list.count);

    for (i = 0; i < all_list.count; ++i) {
        const usbs_device_t *device = &all_list.items[i];
        char                 identity[USBS_IDENTITY_MAX];
        usbs_u32             j;

        /* A local volume GUID path, or (network) a long-path UNC share. */
        USBS_CHECK(strncmp(device->volume_path, "\\\\?\\Volume", 10) == 0 ||
                   (device->bus_type == USBS_BUS_NETWORK &&
                    strncmp(device->volume_path, "\\\\?\\UNC\\", 8) == 0));

        USBS_CHECK(usbs_ok(usbs_device_identity(device, identity, sizeof(identity))));
        /* Only a USB device may ever carry a "usb:" identity. */
        if (device->bus_type != USBS_BUS_USB) {
            USBS_CHECK(strncmp(identity, "usb:", 4) != 0);
        }
        /* A known non-USB bus keys on the volume, never a shared disk serial. */
        if (device->bus_type != USBS_BUS_USB && device->bus_type != USBS_BUS_UNKNOWN) {
            USBS_CHECK(strncmp(identity, "volume:", 7) == 0);
        }

        for (j = 0; j < device->mount_point_count; ++j) {
            if (_stricmp(device->mount_points[j], system_drive) != 0) {
                continue;
            }
            found_system_drive = true;
            USBS_CHECK(device->media_present);
            USBS_CHECK(device->capacity_bytes > 0);
            USBS_CHECK(usbs_device_is_scannable(device, USBS_ENUM_ALL_VOLUMES));
            if (device->bus_type != USBS_BUS_USB) {
                /* Windows To Go aside, the system drive is internal. */
                USBS_CHECK(!usbs_device_is_scannable(device, USBS_ENUM_USB_ONLY));
            }
        }
    }
    USBS_CHECK(found_system_drive);

    usbs_device_list_free(&usb_list);
    usbs_device_list_free(&all_list);
#elif defined(__linux__) || defined(__APPLE__)
    usbs_device_source_t usb_source = usbs_platform_device_source_ex(USBS_ENUM_USB_ONLY);
    usbs_device_source_t all_source = usbs_platform_device_source_ex(USBS_ENUM_ALL_VOLUMES);
    usbs_device_list_t   usb_list;
    usbs_device_list_t   all_list;

    if (!usbs_ok(usbs_device_enumerate(&usb_source, &usb_list))) {
        return;
    }
    if (usbs_ok(usbs_device_enumerate(&all_source, &all_list))) {
        USBS_CHECK(all_list.count == usb_list.count);
        usbs_device_list_free(&all_list);
    }
    usbs_device_list_free(&usb_list);
#else
    usbs_device_source_t source = usbs_platform_device_source_ex(USBS_ENUM_ALL_VOLUMES);
    usbs_device_list_t   list;
    USBS_CHECK(usbs_device_enumerate(&source, &list) == USBS_ERR_UNSUPPORTED);
#endif
}

/* Enumeration must be repeatable and stable across back-to-back calls -
 * true on any host with a real backend, not just Windows, and with no
 * randomness in the sysfs walk or the DiskArbitration/IOKit enumeration,
 * a second real pass should agree with the first barring an actual
 * hotplug event mid-test. */
static void test_enumeration_is_repeatable(void)
{
#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
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
    test_all_volumes_enumeration();
    test_enumeration_is_repeatable();
    return USBS_TEST_RESULT();
}
