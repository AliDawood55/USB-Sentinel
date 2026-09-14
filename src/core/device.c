/*
 * The device model and its pure operations - portable, no windows.h, so
 * these can be tested with a fixture source and no hardware.
 *
 * Lives in core (not platform, despite being introduced in Phase 2 as
 * "device.c" alongside device_win32.c) for the same reason scan.c does:
 * reporting (core-only per ARCHITECTURE.md section 7.4) needs
 * usbs_device_identity() and usbs_bus_type_string() to render a report, and
 * core must have zero outgoing library dependencies - if this stayed in
 * usbs_platform, usbs_reporting would have to link usbs_platform just for
 * two pure string/formatting functions. device_win32.c (the actual Win32
 * device enumeration) still lives in platform and still links this file
 * via usbs_platform's link to usbs_core.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "usbsentinel/device.h"

void usbs_device_init(usbs_device_t *device)
{
    if (device == NULL) {
        return;
    }
    memset(device, 0, sizeof(*device));
}

const char *usbs_bus_type_string(usbs_bus_type_t bus)
{
    switch (bus) {
    case USBS_BUS_UNKNOWN: return "unknown";
    case USBS_BUS_USB:     return "USB";
    case USBS_BUS_SATA:    return "SATA";
    case USBS_BUS_NVME:    return "NVMe";
    case USBS_BUS_SCSI:    return "SCSI";
    case USBS_BUS_SD:      return "SD";
    case USBS_BUS_OTHER:   return "other";
    case USBS_BUS_NETWORK: return "network";
    }
    return "unknown";
}

/* A bus positively identified as something other than USB. UNKNOWN is not
 * on this list: "could not tell" keeps the pre-Phase-17 identity rules. */
static usbs_bool is_known_non_usb_bus(usbs_bus_type_t bus)
{
    return bus != USBS_BUS_USB && bus != USBS_BUS_UNKNOWN;
}

usbs_status_t usbs_device_identity(const usbs_device_t *device,
                                   char                *buf,
                                   size_t               cap)
{
    int      written;
    usbs_bool have_usb_ids;
    usbs_bool have_serial;

    if (device == NULL || buf == NULL || cap == 0) {
        return USBS_ERR_INVALID_ARG;
    }

    have_usb_ids = (device->usb_vid[0] != '\0' && device->usb_pid[0] != '\0');
    /* See device.h: a serial names a physical disk, which on an internal
     * drive is shared by every volume on it. */
    have_serial  = (device->serial[0] != '\0') && !is_known_non_usb_bus(device->bus_type);

    if (have_usb_ids && have_serial) {
        written = snprintf(buf, cap, "usb:%s-%s:%s",
                           device->usb_vid, device->usb_pid, device->serial);
    } else if (have_usb_ids) {
        written = snprintf(buf, cap, "usb:%s-%s",
                           device->usb_vid, device->usb_pid);
    } else if (have_serial) {
        written = snprintf(buf, cap, "serial:%s", device->serial);
    } else {
        written = snprintf(buf, cap, "volume:%s", device->volume_path);
    }

    if (written < 0) {
        return USBS_ERR_INTERNAL;
    }
    if ((size_t)written >= cap) {
        return USBS_ERR_NO_MEMORY; /* truncated */
    }
    return USBS_OK;
}

usbs_bool usbs_device_is_scannable_usb(const usbs_device_t *device)
{
    if (device == NULL) {
        return false;
    }
    return device->bus_type == USBS_BUS_USB && device->media_present;
}

usbs_bool usbs_device_is_scannable(const usbs_device_t *device, usbs_enum_mode_t mode)
{
    if (device == NULL) {
        return false;
    }
    if (mode != USBS_ENUM_ALL_VOLUMES) {
        return usbs_device_is_scannable_usb(device);
    }
    return device->media_present &&
           device->mount_point_count > 0 &&
           device->volume_path[0] != '\0';
}

void usbs_device_list_init(usbs_device_list_t *list)
{
    if (list == NULL) {
        return;
    }
    list->items    = NULL;
    list->count    = 0;
    list->capacity = 0;
}

usbs_status_t usbs_device_list_push(usbs_device_list_t  *list,
                                    const usbs_device_t *device)
{
    if (list == NULL || device == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    if (list->count == list->capacity) {
        size_t         next = (list->capacity == 0) ? 8 : list->capacity * 2;
        usbs_device_t *grown;

        /* Guard the multiplication before handing it to realloc. */
        if (next > SIZE_MAX / sizeof(usbs_device_t)) {
            return USBS_ERR_NO_MEMORY;
        }

        grown = realloc(list->items, next * sizeof(usbs_device_t));
        if (grown == NULL) {
            return USBS_ERR_NO_MEMORY;
        }
        list->items    = grown;
        list->capacity = next;
    }

    list->items[list->count] = *device;
    ++list->count;
    return USBS_OK;
}

void usbs_device_list_free(usbs_device_list_t *list)
{
    if (list == NULL) {
        return;
    }
    free(list->items);
    list->items    = NULL;
    list->count    = 0;
    list->capacity = 0;
}

usbs_status_t usbs_device_enumerate(const usbs_device_source_t *source,
                                    usbs_device_list_t         *out_list)
{
    usbs_status_t status;

    if (source == NULL || out_list == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    usbs_device_list_init(out_list);

    if (source->enumerate == NULL) {
        return USBS_ERR_UNSUPPORTED;
    }

    status = source->enumerate(source->ctx, out_list);
    if (!usbs_ok(status)) {
        usbs_device_list_free(out_list);
    }
    return status;
}
