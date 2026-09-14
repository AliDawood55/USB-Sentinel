/*
 * `usb-sentinel devices` - point-in-time enumeration.
 *
 * Output is human-readable text. The JSON-primary rule in ARCHITECTURE.md
 * section 7.4 governs scan reports, which do not exist yet; this listing is
 * not one.
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "cli.h"
#include "usbsentinel/platform.h"

static void format_size(usbs_u64 bytes, char *buf, size_t cap)
{
    const char *units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    double      value   = (double)bytes;
    size_t      unit    = 0;

    while (value >= 1024.0 && unit + 1 < USBS_ARRAY_LEN(units)) {
        value /= 1024.0;
        ++unit;
    }

    if (unit == 0) {
        snprintf(buf, cap, "%" PRIu64 " B", bytes);
    } else {
        snprintf(buf, cap, "%.1f %s", value, units[unit]);
    }
}

static void print_mount_points(const usbs_device_t *device)
{
    usbs_u32 i;

    if (device->mount_point_count == 0) {
        printf("(no drive letter)");
        return;
    }
    for (i = 0; i < device->mount_point_count; ++i) {
        printf("%s%s", (i > 0) ? ", " : "", device->mount_points[i]);
    }
}

static void print_device(size_t index, const usbs_device_t *device)
{
    char                identity[USBS_IDENTITY_MAX];
    char                capacity[32];
    char                freespace[32];
    usbs_capabilities_t caps;

    printf("[%zu] ", index + 1);
    print_mount_points(device);
    if (device->label[0] != '\0') {
        printf("  %s", device->label);
    }
    printf("\n");

    printf("    volume      %s\n", device->volume_path);
    printf("    bus         %s\n", usbs_bus_type_string(device->bus_type));

    /* Device-level key: volumes sharing a physical device share this value. */
    if (usbs_ok(usbs_device_identity(device, identity, sizeof(identity)))) {
        printf("    device id   %s\n", identity);
    }

    if (device->vendor[0] != '\0' && device->product[0] != '\0') {
        printf("    hardware    %s %s\n", device->vendor, device->product);
    } else if (device->vendor[0] != '\0') {
        printf("    hardware    %s\n", device->vendor);
    } else if (device->product[0] != '\0') {
        printf("    hardware    %s\n", device->product);
    }

    if (!device->media_present) {
        printf("    media       not present\n");
        return;
    }

    printf("    filesystem  %s\n",
           device->filesystem[0] ? device->filesystem : "(unknown)");

    format_size(device->capacity_bytes, capacity, sizeof(capacity));
    format_size(device->free_bytes, freespace, sizeof(freespace));
    printf("    capacity    %s (%s free)\n", capacity, freespace);

    /*
     * Capability state is printed, not hidden: a silently skipped check is
     * worse than no check (ARCHITECTURE.md section 7.3).
     */
    usbs_capabilities_init(&caps);
    if (usbs_ok(usbs_platform_probe_capabilities(device, &caps))) {
        printf("    raw volume  %s\n",
               caps.can_read_raw_volume
                   ? "available"
                   : "unavailable (requires elevation)");
        printf("    raw disk    %s\n",
               caps.can_read_physical_disk
                   ? "available"
                   : "unavailable (requires elevation)");
    }
}

usbs_status_t usbs_cli_cmd_devices(int argc, char **argv)
{
    usbs_device_source_t source;
    usbs_device_list_t   list;
    usbs_status_t        status;
    usbs_bool            show_all = false;
    size_t               shown = 0;
    size_t               i;
    int                  arg;

    for (arg = 2; arg < argc; ++arg) {
        if (strcmp(argv[arg], "--all") == 0) {
            show_all = true;
        } else {
            fprintf(stderr, "devices: unknown option: %s\n", argv[arg]);
            return USBS_ERR_INVALID_ARG;
        }
    }

    /* --all also asks the backend for volumes only that mode enumerates
     * (mapped network drives on Windows - platform.h). */
    source = usbs_platform_device_source_ex(show_all ? USBS_ENUM_ALL_VOLUMES
                                                     : USBS_ENUM_USB_ONLY);
    status = usbs_device_enumerate(&source, &list);
    if (!usbs_ok(status)) {
        fprintf(stderr, "devices: enumeration failed: %s\n",
                usbs_status_string(status));
        return status;
    }

    for (i = 0; i < list.count; ++i) {
        const usbs_device_t *device = &list.items[i];

        if (!show_all && device->bus_type != USBS_BUS_USB) {
            continue;
        }
        if (shown > 0) {
            printf("\n");
        }
        print_device(shown, device);
        ++shown;
    }

    if (shown == 0) {
        printf("No %sdevices found.\n", show_all ? "" : "USB ");
        if (!show_all) {
            printf("Use --all to list every volume.\n");
        }
    } else {
        printf("\n%zu device(s) listed, %zu volume(s) examined.\n",
               shown, list.count);
    }

    printf("\nScanning is read-only: no file was opened for writing.\n");

    usbs_device_list_free(&list);
    return USBS_OK;
}
