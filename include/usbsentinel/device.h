/*
 * USB Sentinel - storage device model.
 *
 * This header is portable C17 and must stay free of platform headers. The
 * acquisition of these structures is the platform module's job; see
 * ARCHITECTURE.md section 7 for the enumeration strategy.
 *
 * Text fields are UTF-8. The platform layer converts from UTF-16 at the Win32
 * boundary so nothing above it has to deal with wide strings.
 */
#ifndef USBSENTINEL_DEVICE_H
#define USBSENTINEL_DEVICE_H

#include "usbsentinel/error.h"
#include "usbsentinel/types.h"

/*
 * Sized for paths, not for Windows drive letters (Phase 14, ARCHITECTURE.md
 * section 20.1).
 *
 * These were originally cut to the exact Win32 shapes: 64 for
 * "\\?\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\" (49 chars + NUL) and 8
 * for "E:". Both are wrong for any POSIX host, where there is no volume GUID
 * and the volume path *is* a mount path - "/media/alice/SANDISK_ULTRA_64GB",
 * "/Volumes/Untitled 1" - routinely past 64 bytes, and where a mount point is
 * a full path rather than a two-character drive name.
 *
 * 8 was in fact already too small on Windows: a volume mounted into a folder
 * rather than a drive letter ("C:\Mounts\MyUSB") was silently truncated to
 * seven characters by fill_mount_points() in device_win32.c. So this is a
 * latent-bug fix on the existing platform as much as it is preparation for
 * the next one.
 *
 * 512 is chosen over PATH_MAX (4096 on Linux) deliberately. usbs_device_t is
 * a flat by-value POD pushed into usbs_device_list_t, so every byte here is
 * multiplied by MOUNT_POINTS_MAX and again by the device count; 512 covers
 * every real mount path while keeping the struct near 2.5 KB instead of past
 * 16 KB. Paths longer than this are truncated, as they were before - bounded
 * truncation, never overflow.
 */
#define USBS_VOLUME_PATH_MAX  512
#define USBS_MOUNT_POINT_MAX  512
#define USBS_MOUNT_POINTS_MAX 4
#define USBS_LABEL_MAX        128
#define USBS_FS_NAME_MAX      32
#define USBS_ID_STR_MAX       128

/*
 * Big enough that usbs_device_identity() can never fail on a well-formed
 * device - derived, not a round number, so it cannot silently drift out of
 * step with the fields it has to hold (Phase 14, ARCHITECTURE.md section
 * 20.1).
 *
 * The binding case is the "volume:<volume_path>" fallback: 7 + up to
 * USBS_VOLUME_PATH_MAX - 1 characters + NUL. While volume_path was 64 this
 * fit inside a flat 160 with room to spare, so the fallback was infallible
 * by accident. At 512 a literal 160 would start returning
 * USBS_ERR_NO_MEMORY for ordinary POSIX mount paths, which would take out
 * the storage key and the report with it - the failure would surface far
 * from its cause. Deriving it keeps "the fallback always fits" a property of
 * the header rather than a coincidence of two numbers.
 *
 * The longest alternative, "usb:VVVV-PPPP:<serial>", needs
 * USBS_ID_STR_MAX + 15 and is comfortably inside the same bound.
 */
#define USBS_IDENTITY_MAX     (USBS_VOLUME_PATH_MAX + 32)

typedef enum usbs_bus_type {
    USBS_BUS_UNKNOWN = 0,
    USBS_BUS_USB,
    USBS_BUS_SATA,
    USBS_BUS_NVME,
    USBS_BUS_SCSI,
    USBS_BUS_SD,
    USBS_BUS_OTHER
} usbs_bus_type_t;

typedef struct usbs_device {
    /* Stable volume path, with trailing separator. The scanner walks this,
     * never a drive letter (ARCHITECTURE.md section 7.2). */
    char volume_path[USBS_VOLUME_PATH_MAX];

    /* Where the volume is reachable in the filesystem namespace: a drive
     * letter such as "E:" or a folder mount on Windows, a mount path such as
     * "/media/alice/USB" on POSIX. A volume may have none, or several. */
    char     mount_points[USBS_MOUNT_POINTS_MAX][USBS_MOUNT_POINT_MAX];
    usbs_u32 mount_point_count;

    char     label[USBS_LABEL_MAX];
    char     filesystem[USBS_FS_NAME_MAX];
    usbs_u64 capacity_bytes;
    usbs_u64 free_bytes;

    usbs_bus_type_t bus_type;
    usbs_u32        disk_number;
    usbs_bool       has_disk_number;

    /* Best-effort device identity. Empty when the device exposes none. */
    char vendor[USBS_ID_STR_MAX];
    char product[USBS_ID_STR_MAX];
    char serial[USBS_ID_STR_MAX];
    char usb_vid[5];  /* "0781", empty when not a USB device */
    char usb_pid[5];  /* "5583", empty when not a USB device */

    usbs_bool removable_media;
    usbs_bool media_present;
} usbs_device_t;

typedef struct usbs_device_list {
    usbs_device_t *items;
    size_t         count;
    size_t         capacity;
} usbs_device_list_t;

/*
 * Enumeration seam. The Win32 implementation is one source; tests supply a
 * fixture source so they run with no hardware attached.
 */
typedef struct usbs_device_source {
    usbs_status_t (*enumerate)(void *ctx, usbs_device_list_t *out_list);
    void *ctx;
} usbs_device_source_t;

/* --- device_t helpers (portable) --- */

/* Zeroes `device`. */
void usbs_device_init(usbs_device_t *device);

/* Returns a short name for `bus`, e.g. "USB". Never NULL. */
const char *usbs_bus_type_string(usbs_bus_type_t bus);

/*
 * Writes a durable identity key for `device` into `buf`.
 *
 * Preference order, per ARCHITECTURE.md section 7.2:
 *   1. "usb:VID-PID:SERIAL"   both USB ids and a serial known
 *   2. "usb:VID-PID"          USB ids known, no serial
 *   3. "serial:SERIAL"        serial known, not identified as USB
 *   4. "volume:<volume_path>" fallback; stable until the volume is reformatted
 *
 * A drive letter is never part of the key.
 *
 * NOTE: this identifies the *device*, not the volume. Several volumes on one
 * physical device share a key by design. A volume-level key (device key plus
 * volume GUID) will be needed when `storage` lands; it is not added here
 * because nothing consumes it yet.
 *
 * Returns USBS_ERR_INVALID_ARG on a NULL argument, USBS_ERR_NO_MEMORY if `cap`
 * is too small.
 */
usbs_status_t usbs_device_identity(const usbs_device_t *device,
                                   char                *buf,
                                   size_t               cap);

/* True when the device is a USB-attached volume with media present. */
usbs_bool usbs_device_is_scannable_usb(const usbs_device_t *device);

/* --- device_list_t (portable) --- */

void          usbs_device_list_init(usbs_device_list_t *list);
usbs_status_t usbs_device_list_push(usbs_device_list_t  *list,
                                    const usbs_device_t *device);
void          usbs_device_list_free(usbs_device_list_t *list);

/*
 * Enumerates through `source`. `out_list` is initialized by this call and must
 * be released with usbs_device_list_free() on success.
 */
usbs_status_t usbs_device_enumerate(const usbs_device_source_t *source,
                                    usbs_device_list_t         *out_list);

#endif /* USBSENTINEL_DEVICE_H */
