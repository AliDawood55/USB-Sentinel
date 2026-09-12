/*
 * macOS device enumeration and capability probing, via DiskArbitration and
 * IOKit. Compiled only on Apple (ARCHITECTURE.md section 21.3); Linux gets
 * device_linux.c, and any other UNIX gets device_posix_unsupported.c.
 *
 * Division of labor between the two frameworks, chosen deliberately rather
 * than reaching for IOKit everywhere: DiskArbitration already resolves
 * mount point, label, filesystem, capacity, removable, and - via
 * kDADiskDescriptionDeviceProtocolKey - the bus protocol itself, all from
 * one DADiskCopyDescription() call. IOKit's registry is walked separately,
 * and only for what DiskArbitration does not expose: USB VID/PID/serial.
 * This mirrors device_linux.c's own division (mountinfo for volume-level
 * facts, a sysfs ancestry walk only for USB identity) even though the
 * concrete APIs are unrelated - each platform's higher-level facility
 * supplies what it is naturally good at, and the lower-level registry walk
 * is reserved for the one thing that needs it.
 *
 * HONESTY ABOUT WHAT COULD NOT BE VERIFIED (ARCHITECTURE.md section 21):
 * there is no Mac available to build or run this file against - not even
 * the "does this even compile" question, let alone real hardware. Two
 * different confidence levels are marked explicitly in the comments below:
 *
 *   - IOKit/DiskArbitration/CoreFoundation KEY CONSTANTS (kIOMediaSizeKey,
 *     kDADiskDescriptionVolumePathKey, etc.) are the SDK's own named
 *     symbols, not hand-typed strings - if a name is wrong or has moved,
 *     this FAILS TO COMPILE on the macOS CI job, which is a loud, specific,
 *     fixable signal rather than a silent runtime misbehavior. This is the
 *     same reasoning device_linux.c's own comments give for preferring a
 *     compile error over an assumption.
 *   - The USB device's own property KEYS ("idVendor", "idProduct", "USB
 *     Serial Number", ...) have no equivalent stable symbolic constant
 *     available here and are plain string literals, matched against what
 *     `ioreg -p IOUSB -l` shows on real hardware and what numerous other
 *     open-source USB tooling already relies on - reasonably high
 *     confidence, but NOT compiler-checked, and NOT run against a real
 *     USB device by this project. This is exactly the gap
 *     ARCHITECTURE.md section 21.4's beta-tester process exists to close.
 *
 * The negative path - a non-USB-ancestored volume correctly stays
 * USBS_BUS_UNKNOWN - is proven in CI via a real (if virtual) hdiutil disk
 * image, the direct macOS analogue of Linux's loop-device job. The
 * positive path (does this actually find a real USB stick's real
 * VID/PID/serial) cannot be proven without hardware CI does not have.
 */
#include <string.h>
#include <sys/statvfs.h>

#include <CoreFoundation/CoreFoundation.h>
#include <DiskArbitration/DiskArbitration.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOMedia.h>

#include "usbsentinel/log.h"
#include "usbsentinel/path.h"
#include "usbsentinel/platform.h"

/* --- small CF/IOKit helpers --- */

/* Copies a CFStringRef into a UTF-8 C buffer. Never partially writes: on
 * any failure `out` is left as an empty string, matching read_sysfs_string
 * ()'s honest-empty-on-failure contract in device_linux.c. */
static void cfstring_to_utf8(CFStringRef str, char *out, size_t cap)
{
    out[0] = '\0';
    if (str == NULL || cap == 0) {
        return;
    }
    if (!CFStringGetCString(str, out, (CFIndex)cap, kCFStringEncodingUTF8)) {
        out[0] = '\0';
    }
}

/* Reads a CFNumberRef dictionary value as a u64. Returns false (and leaves
 * `*out` untouched) if the key is absent or not a number - callers already
 * treat a missing/failed read the same way Linux's read_sysfs_u64() does:
 * an honest zero, not a fabricated one. */
static usbs_bool cfdict_get_u64(CFDictionaryRef dict, CFStringRef key, usbs_u64 *out)
{
    CFNumberRef number;
    int64_t     value = 0;

    if (dict == NULL) {
        return false;
    }
    number = (CFNumberRef)CFDictionaryGetValue(dict, key);
    if (number == NULL || CFGetTypeID(number) != CFNumberGetTypeID()) {
        return false;
    }
    if (!CFNumberGetValue(number, kCFNumberSInt64Type, &value)) {
        return false;
    }
    *out = (usbs_u64)value;
    return true;
}

static usbs_bool cfdict_get_bool(CFDictionaryRef dict, CFStringRef key, usbs_bool default_value)
{
    CFBooleanRef value;
    if (dict == NULL) {
        return default_value;
    }
    value = (CFBooleanRef)CFDictionaryGetValue(dict, key);
    if (value == NULL || CFGetTypeID(value) != CFBooleanGetTypeID()) {
        return default_value;
    }
    return CFBooleanGetValue(value) ? true : false;
}

/* --- bus type, from DiskArbitration's own DeviceProtocol string --- */

/*
 * Unlike device_linux.c, which deliberately classifies ONLY "is this USB"
 * and leaves everything else USBS_BUS_UNKNOWN (Linux's libata SATA-via-SCSI
 * translation makes a reliable non-USB distinction from sysfs alone a
 * materially bigger undertaking than that phase's scope), macOS maps the
 * full set: DeviceProtocol is a single field DiskArbitration has already
 * resolved for us, not something this project has to derive itself the
 * way the sysfs ancestry walk does, so there is no equivalent reason to
 * hold back here.
 */
static usbs_bus_type_t bus_type_from_protocol(CFStringRef protocol)
{
    struct { CFStringRef name; usbs_bus_type_t bus; } table[6];
    size_t i;

    if (protocol == NULL) {
        return USBS_BUS_UNKNOWN;
    }

    table[0].name = CFSTR("USB");           table[0].bus = USBS_BUS_USB;
    table[1].name = CFSTR("ATA");           table[1].bus = USBS_BUS_SATA;
    table[2].name = CFSTR("Serial ATA");    table[2].bus = USBS_BUS_SATA;
    table[3].name = CFSTR("PCI-Express");   table[3].bus = USBS_BUS_NVME;
    table[4].name = CFSTR("SCSI");          table[4].bus = USBS_BUS_SCSI;
    table[5].name = CFSTR("Secure Digital"); table[5].bus = USBS_BUS_SD;

    for (i = 0; i < USBS_ARRAY_LEN(table); ++i) {
        if (CFStringCompare(protocol, table[i].name, kCFCompareCaseInsensitive) ==
            kCFCompareEqualTo) {
            return table[i].bus;
        }
    }
    return USBS_BUS_OTHER;
}

/* --- IOKit registry walk: USB VID/PID/serial only --- */

/*
 * Walks up from `media_service`'s registry ancestry looking for a real USB
 * device node - conforming to "IOUSBHostDevice" (modern, macOS 10.11+) or
 * "IOUSBDevice" (legacy); both are checked since either can be present
 * depending on OS version and controller. On a match, fills usb_vid/
 * usb_pid (formatted as lowercase 4-hex-digit strings from the integer
 * idVendor/idProduct properties, matching sysfs's own already-hex-string
 * convention on Linux and Windows's VID_xxxx/PID_xxxx extraction) and
 * vendor/product/serial from the corresponding string properties.
 *
 * The property KEY STRINGS here ("idVendor", "idProduct", "USB Serial
 * Number", "USB Vendor Name", "USB Product Name") are this file's one
 * genuinely unverified piece - see this file's header comment. Bounded to
 * 20 levels (device_win32.c's PnP walk uses 8; IOKit registry paths can be
 * a few levels deeper than a PnP device stack) purely as a defensive bound
 * against a registry shape this file did not anticipate, not because a
 * real chain is expected to be anywhere near that deep.
 */
static void usb_ancestor_walk(io_service_t media_service, usbs_device_t *device)
{
    io_service_t current;
    int          depth;

    current = media_service;
    IOObjectRetain(current);

    for (depth = 0; depth < 20; ++depth) {
        io_service_t parent = IO_OBJECT_NULL;

        if (IOObjectConformsTo(current, "IOUSBHostDevice") ||
            IOObjectConformsTo(current, "IOUSBDevice")) {
            CFNumberRef vendor_id  = (CFNumberRef)IORegistryEntryCreateCFProperty(
                current, CFSTR("idVendor"), kCFAllocatorDefault, 0);
            CFNumberRef product_id = (CFNumberRef)IORegistryEntryCreateCFProperty(
                current, CFSTR("idProduct"), kCFAllocatorDefault, 0);
            CFStringRef serial     = (CFStringRef)IORegistryEntryCreateCFProperty(
                current, CFSTR("USB Serial Number"), kCFAllocatorDefault, 0);
            CFStringRef vendor_str = (CFStringRef)IORegistryEntryCreateCFProperty(
                current, CFSTR("USB Vendor Name"), kCFAllocatorDefault, 0);
            CFStringRef product_str = (CFStringRef)IORegistryEntryCreateCFProperty(
                current, CFSTR("USB Product Name"), kCFAllocatorDefault, 0);

            device->bus_type = USBS_BUS_USB;

            if (vendor_id != NULL && CFGetTypeID(vendor_id) == CFNumberGetTypeID()) {
                int64_t v = 0;
                if (CFNumberGetValue(vendor_id, kCFNumberSInt64Type, &v)) {
                    snprintf(device->usb_vid, sizeof(device->usb_vid), "%04llx",
                            (unsigned long long)(v & 0xFFFFu));
                }
            }
            if (product_id != NULL && CFGetTypeID(product_id) == CFNumberGetTypeID()) {
                int64_t v = 0;
                if (CFNumberGetValue(product_id, kCFNumberSInt64Type, &v)) {
                    snprintf(device->usb_pid, sizeof(device->usb_pid), "%04llx",
                            (unsigned long long)(v & 0xFFFFu));
                }
            }
            if (serial != NULL && CFGetTypeID(serial) == CFStringGetTypeID()) {
                cfstring_to_utf8(serial, device->serial, sizeof(device->serial));
            }
            if (vendor_str != NULL && CFGetTypeID(vendor_str) == CFStringGetTypeID()) {
                cfstring_to_utf8(vendor_str, device->vendor, sizeof(device->vendor));
            }
            if (product_str != NULL && CFGetTypeID(product_str) == CFStringGetTypeID()) {
                cfstring_to_utf8(product_str, device->product, sizeof(device->product));
            }

            if (vendor_id != NULL) CFRelease(vendor_id);
            if (product_id != NULL) CFRelease(product_id);
            if (serial != NULL) CFRelease(serial);
            if (vendor_str != NULL) CFRelease(vendor_str);
            if (product_str != NULL) CFRelease(product_str);

            IOObjectRelease(current);
            return;
        }

        if (IORegistryEntryGetParentEntry(current, kIOServicePlane, &parent) != KERN_SUCCESS ||
            parent == IO_OBJECT_NULL) {
            IOObjectRelease(current);
            return; /* reached the top with no USB ancestor found */
        }
        IOObjectRelease(current);
        current = parent;
    }
    IOObjectRelease(current);
}

/* --- per-volume data collection --- */

static void fill_from_disk_arbitration(DASessionRef session, const char *bsd_name,
                                       usbs_device_t *device)
{
    DADiskRef       disk;
    CFDictionaryRef description;

    disk = DADiskCreateFromBSDName(kCFAllocatorDefault, session, bsd_name);
    if (disk == NULL) {
        return;
    }

    description = DADiskCopyDescription(disk);
    if (description != NULL) {
        CFURLRef    volume_url;
        CFStringRef protocol;

        device->removable_media =
            cfdict_get_bool(description, kDADiskDescriptionMediaRemovableKey, false);
        (void)cfdict_get_u64(description, kDADiskDescriptionMediaSizeKey,
                             &device->capacity_bytes);

        protocol = (CFStringRef)CFDictionaryGetValue(description,
                                                      kDADiskDescriptionDeviceProtocolKey);
        device->bus_type = bus_type_from_protocol(protocol);

        cfstring_to_utf8(
            (CFStringRef)CFDictionaryGetValue(description, kDADiskDescriptionVolumeNameKey),
            device->label, sizeof(device->label));
        cfstring_to_utf8(
            (CFStringRef)CFDictionaryGetValue(description, kDADiskDescriptionVolumeKindKey),
            device->filesystem, sizeof(device->filesystem));

        volume_url = (CFURLRef)CFDictionaryGetValue(description,
                                                     kDADiskDescriptionVolumePathKey);
        if (volume_url != NULL) {
            char mount_point[USBS_MOUNT_POINT_MAX];
            if (CFURLGetFileSystemRepresentation(volume_url, true,
                                                 (UInt8 *)mount_point,
                                                 (CFIndex)sizeof(mount_point))) {
                device->media_present = true;
                if (device->mount_point_count < USBS_MOUNT_POINTS_MAX) {
                    snprintf(device->mount_points[device->mount_point_count],
                            USBS_MOUNT_POINT_MAX, "%s", mount_point);
                    ++device->mount_point_count;
                }
                usbs_path_join(device->volume_path, sizeof(device->volume_path),
                              mount_point, "");

                /* DiskArbitration's own MediaSize (above) is the whole
                 * device's capacity; free space needs a live statvfs() on
                 * the mount point, the same call device_linux.c makes for
                 * the same reason (there is no DiskArbitration key for
                 * free space, only total size). macOS implements POSIX
                 * statvfs(), so this is the identical call, not a
                 * BSD-specific statfs() substitute. */
                {
                    struct statvfs vfs;
                    if (statvfs(mount_point, &vfs) == 0) {
                        device->free_bytes = (usbs_u64)vfs.f_bavail * (usbs_u64)vfs.f_frsize;
                    }
                }
            }
        }

        /* USB identity is the one thing DiskArbitration itself does not
         * expose - DADiskCopyIOMedia() bridges back to the same IOKit
         * object this disk's enumeration already came from, letting the
         * ancestor walk start from exactly the right place. */
        {
            io_service_t media_service = DADiskCopyIOMedia(disk);
            if (media_service != IO_OBJECT_NULL) {
                usb_ancestor_walk(media_service, device);
                IOObjectRelease(media_service);
            }
        }

        CFRelease(description);
    }

    CFRelease(disk);
}

/* --- enumeration --- */

static usbs_status_t macos_enumerate(void *ctx, usbs_device_list_t *out_list)
{
    DASessionRef    session;
    CFDictionaryRef matching;
    io_iterator_t   iterator = IO_OBJECT_NULL;
    io_service_t    media_service;
    kern_return_t   kr;

    USBS_UNUSED(ctx);

    session = DASessionCreate(kCFAllocatorDefault);
    if (session == NULL) {
        USBS_LOG_E("DASessionCreate failed");
        return USBS_ERR_INTERNAL;
    }

    matching = IOServiceMatching(kIOMediaClass);
    if (matching == NULL) {
        CFRelease(session);
        return USBS_ERR_INTERNAL;
    }

    kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &iterator);
    if (kr != KERN_SUCCESS) {
        USBS_LOG_E("IOServiceGetMatchingServices failed: %d", (int)kr);
        CFRelease(session);
        return USBS_ERR_INTERNAL;
    }

    while ((media_service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        usbs_device_t   device;
        CFStringRef     bsd_name_ref;
        char            bsd_name[64];
        usbs_bool       is_leaf;
        usbs_status_t   push_status;

        /*
         * kIOMediaLeafKey is true exactly for a volume that has no further
         * partitioning below it - a plain partition, or an unpartitioned
         * whole disk. This is the direct macOS analogue of
         * device_linux.c's own "is_partition_entry() OR NOT
         * disk_has_partition_children()" inclusion rule, expressed as a
         * single IOKit-provided property instead of something this
         * project has to derive itself by listing sysfs children.
         */
        is_leaf = false;
        {
            CFBooleanRef leaf = (CFBooleanRef)IORegistryEntryCreateCFProperty(
                media_service, CFSTR(kIOMediaLeafKey), kCFAllocatorDefault, 0);
            if (leaf != NULL) {
                if (CFGetTypeID(leaf) == CFBooleanGetTypeID()) {
                    is_leaf = CFBooleanGetValue(leaf) ? true : false;
                }
                CFRelease(leaf);
            }
        }
        if (!is_leaf) {
            IOObjectRelease(media_service);
            continue;
        }

        bsd_name_ref = (CFStringRef)IORegistryEntryCreateCFProperty(
            media_service, CFSTR(kIOBSDNameKey), kCFAllocatorDefault, 0);
        if (bsd_name_ref == NULL) {
            IOObjectRelease(media_service);
            continue; /* no BSD name: cannot be reached via DiskArbitration */
        }
        cfstring_to_utf8(bsd_name_ref, bsd_name, sizeof(bsd_name));
        CFRelease(bsd_name_ref);

        usbs_device_init(&device);

        fill_from_disk_arbitration(session, bsd_name, &device);

        push_status = usbs_device_list_push(out_list, &device);
        IOObjectRelease(media_service);
        if (!usbs_ok(push_status)) {
            IOObjectRelease(iterator);
            CFRelease(session);
            return push_status;
        }
    }

    IOObjectRelease(iterator);
    CFRelease(session);
    return USBS_OK;
}

usbs_device_source_t usbs_platform_device_source(void)
{
    usbs_device_source_t source;
    source.enumerate = macos_enumerate;
    source.ctx       = NULL;
    return source;
}

/* --- capability probing (deferred) --- */

/*
 * Deliberately deferred for all of Phase 14b, on every platform (see
 * device_linux.c's identical decision and reasoning) - every caller
 * already degrades gracefully without it.
 */
void usbs_capabilities_init(usbs_capabilities_t *caps)
{
    if (caps != NULL) {
        memset(caps, 0, sizeof(*caps));
    }
}

usbs_status_t usbs_platform_probe_capabilities(const usbs_device_t *device,
                                               usbs_capabilities_t *out_caps)
{
    if (device == NULL || out_caps == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    usbs_capabilities_init(out_caps);
    return USBS_ERR_UNSUPPORTED;
}
