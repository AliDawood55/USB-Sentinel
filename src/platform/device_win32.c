/*
 * Win32 half of the platform module. This is the ONLY translation unit in the
 * project permitted to include <windows.h> (ARCHITECTURE.md section 2).
 *
 * Strategy, per ARCHITECTURE.md section 7.1:
 *   1. Volume APIs enumerate.
 *   2. IOCTL_STORAGE_QUERY_PROPERTY decides bus type -- GetDriveType is never
 *      used as a USB test.
 *   3. SetupAPI/CfgMgr32 supply USB VID/PID.
 *
 * Every device handle here is opened with dwDesiredAccess = 0, which needs no
 * elevation and still permits FILE_ANY_ACCESS IOCTLs.
 */
#include <stdlib.h>
#include <string.h>

#include "usbsentinel/log.h"
#include "usbsentinel/platform.h"

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#define INITGUID
#include <windows.h>

#include <cfgmgr32.h>
#include <setupapi.h>
#include <winioctl.h>

/* --- small helpers --- */

usbs_status_t usbs_platform_status_from_win32(unsigned long win32_error)
{
    switch (win32_error) {
    case ERROR_SUCCESS:
        return USBS_OK;
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_PRIVILEGE_NOT_HELD:
        return USBS_ERR_ACCESS_DENIED;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_NO_MORE_FILES:
    case ERROR_DEV_NOT_EXIST:
        return USBS_ERR_NOT_FOUND;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:
        return USBS_ERR_NO_MEMORY;
    case ERROR_INVALID_PARAMETER:
    case ERROR_INVALID_NAME:
        return USBS_ERR_INVALID_ARG;
    case ERROR_NOT_SUPPORTED:
    case ERROR_INVALID_FUNCTION:
        return USBS_ERR_UNSUPPORTED;
    case ERROR_NOT_READY:
    case ERROR_DEVICE_NOT_CONNECTED:
    case ERROR_MEDIA_CHANGED:
    case ERROR_UNRECOGNIZED_MEDIA:
    case ERROR_IO_DEVICE:
    case ERROR_CRC:
        return USBS_ERR_IO;
    default:
        return USBS_ERR_INTERNAL;
    }
}

/* Converts a UTF-16 string to UTF-8. Truncation is reported, not fatal. */
static usbs_bool utf8_from_wide(const wchar_t *src, char *dst, size_t cap)
{
    int written;

    if (dst == NULL || cap == 0) {
        return false;
    }
    dst[0] = '\0';
    if (src == NULL) {
        return false;
    }

    written = WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, (int)cap,
                                  NULL, NULL);
    if (written <= 0) {
        dst[0] = '\0';
        return false;
    }
    return true;
}

/* Copies an ASCII descriptor field, trimming the padding the spec allows. */
static void copy_trimmed(const char *src, char *dst, size_t cap)
{
    size_t start = 0;
    size_t end;
    size_t len;

    if (dst == NULL || cap == 0) {
        return;
    }
    dst[0] = '\0';
    if (src == NULL) {
        return;
    }

    end = strlen(src);
    while (start < end && (unsigned char)src[start] <= ' ') {
        ++start;
    }
    while (end > start && (unsigned char)src[end - 1] <= ' ') {
        --end;
    }

    len = end - start;
    if (len >= cap) {
        len = cap - 1;
    }
    memcpy(dst, src + start, len);
    dst[len] = '\0';
}

static usbs_bus_type_t bus_type_from_storage(STORAGE_BUS_TYPE bus)
{
    switch (bus) {
    case BusTypeUsb:   return USBS_BUS_USB;
    case BusTypeSata:  return USBS_BUS_SATA;
    case BusTypeNvme:  return USBS_BUS_NVME;
    case BusTypeScsi:  return USBS_BUS_SCSI;
    case BusTypeSd:
    case BusTypeMmc:   return USBS_BUS_SD;
    case BusTypeUnknown: return USBS_BUS_UNKNOWN;
    default:           return USBS_BUS_OTHER;
    }
}

/*
 * Opens a device path with no access rights. This succeeds unelevated and
 * still allows FILE_ANY_ACCESS IOCTLs -- the basis of the whole least-privilege
 * design in ARCHITECTURE.md section 7.3.
 */
static HANDLE open_device_zero_access(const wchar_t *path)
{
    return CreateFileW(path,
                       0,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL,
                       OPEN_EXISTING,
                       0,
                       NULL);
}

/* Strips one trailing backslash; CreateFileW rejects volume paths that keep it. */
static void strip_trailing_slash(wchar_t *path)
{
    size_t len = wcslen(path);
    if (len > 0 && path[len - 1] == L'\\') {
        path[len - 1] = L'\0';
    }
}

/* --- per-volume data collection --- */

static usbs_bool query_disk_number(HANDLE volume, usbs_u32 *out_number)
{
    STORAGE_DEVICE_NUMBER number;
    DWORD                 returned = 0;

    if (!DeviceIoControl(volume, IOCTL_STORAGE_GET_DEVICE_NUMBER,
                         NULL, 0, &number, sizeof(number), &returned, NULL)) {
        return false;
    }
    *out_number = (usbs_u32)number.DeviceNumber;
    return true;
}

/* Fills bus type, vendor, product, serial and removable flag. */
static usbs_bool query_storage_descriptor(HANDLE volume, usbs_device_t *device)
{
    STORAGE_PROPERTY_QUERY     query;
    STORAGE_DEVICE_DESCRIPTOR *desc;
    BYTE                       buffer[1024];
    DWORD                      returned = 0;

    memset(&query, 0, sizeof(query));
    query.PropertyId = StorageDeviceProperty;
    query.QueryType  = PropertyStandardQuery;

    memset(buffer, 0, sizeof(buffer));
    if (!DeviceIoControl(volume, IOCTL_STORAGE_QUERY_PROPERTY,
                         &query, sizeof(query),
                         buffer, sizeof(buffer), &returned, NULL)) {
        return false;
    }
    if (returned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        return false;
    }

    desc = (STORAGE_DEVICE_DESCRIPTOR *)buffer;

    device->bus_type        = bus_type_from_storage(desc->BusType);
    device->removable_media = desc->RemovableMedia ? true : false;

    /* Offsets are byte offsets into this same buffer; 0 means absent. */
    if (desc->VendorIdOffset != 0 && desc->VendorIdOffset < returned) {
        copy_trimmed((const char *)buffer + desc->VendorIdOffset,
                     device->vendor, sizeof(device->vendor));
    }
    if (desc->ProductIdOffset != 0 && desc->ProductIdOffset < returned) {
        copy_trimmed((const char *)buffer + desc->ProductIdOffset,
                     device->product, sizeof(device->product));
    }
    if (desc->SerialNumberOffset != 0 && desc->SerialNumberOffset < returned) {
        copy_trimmed((const char *)buffer + desc->SerialNumberOffset,
                     device->serial, sizeof(device->serial));
    }
    return true;
}

static void fill_volume_info(const wchar_t *volume_with_slash,
                             usbs_device_t *device)
{
    wchar_t        label[USBS_LABEL_MAX];
    wchar_t        fs[USBS_FS_NAME_MAX];
    ULARGE_INTEGER free_bytes;
    ULARGE_INTEGER total_bytes;

    label[0] = L'\0';
    fs[0]    = L'\0';

    if (GetVolumeInformationW(volume_with_slash,
                              label, (DWORD)USBS_ARRAY_LEN(label),
                              NULL, NULL, NULL,
                              fs, (DWORD)USBS_ARRAY_LEN(fs))) {
        device->media_present = true;
        utf8_from_wide(label, device->label, sizeof(device->label));
        utf8_from_wide(fs, device->filesystem, sizeof(device->filesystem));
    } else {
        /* ERROR_NOT_READY here means an empty reader slot, not a failure. */
        device->media_present = false;
    }

    if (device->media_present &&
        GetDiskFreeSpaceExW(volume_with_slash, NULL, &total_bytes,
                            &free_bytes)) {
        device->capacity_bytes = (usbs_u64)total_bytes.QuadPart;
        device->free_bytes     = (usbs_u64)free_bytes.QuadPart;
    }
}

static void fill_mount_points(const wchar_t *volume_with_slash,
                              usbs_device_t *device)
{
    wchar_t *names = NULL;
    DWORD    needed = 0;
    wchar_t *cursor;

    /* Multi-sz out-parameter: ask for the size, then fetch. */
    if (GetVolumePathNamesForVolumeNameW(volume_with_slash, NULL, 0, &needed)) {
        return; /* no names */
    }
    if (GetLastError() != ERROR_MORE_DATA || needed == 0) {
        return;
    }

    names = (wchar_t *)calloc(needed, sizeof(wchar_t));
    if (names == NULL) {
        return;
    }

    if (GetVolumePathNamesForVolumeNameW(volume_with_slash, names, needed,
                                         &needed)) {
        for (cursor = names;
             *cursor != L'\0' &&
             device->mount_point_count < USBS_MOUNT_POINTS_MAX;
             cursor += wcslen(cursor) + 1) {
            wchar_t trimmed[USBS_MOUNT_POINT_MAX];
            size_t  len = wcslen(cursor);

            /* "E:\" -> "E:"; longer mount-point paths are kept truncated. */
            if (len > 0 && cursor[len - 1] == L'\\') {
                --len;
            }
            if (len >= USBS_ARRAY_LEN(trimmed)) {
                len = USBS_ARRAY_LEN(trimmed) - 1;
            }
            memcpy(trimmed, cursor, len * sizeof(wchar_t));
            trimmed[len] = L'\0';

            utf8_from_wide(trimmed,
                           device->mount_points[device->mount_point_count],
                           USBS_MOUNT_POINT_MAX);
            ++device->mount_point_count;
        }
    }

    free(names);
}

/* --- USB VID/PID via SetupAPI + CfgMgr32 --- */

static usbs_bool parse_vid_pid(const wchar_t *device_id, usbs_device_t *device)
{
    const wchar_t *vid = wcsstr(device_id, L"VID_");
    const wchar_t *pid = wcsstr(device_id, L"PID_");
    wchar_t        buf[5];
    int            i;

    if (vid == NULL || pid == NULL) {
        return false;
    }

    for (i = 0; i < 4; ++i) {
        buf[i] = vid[4 + i];
    }
    buf[4] = L'\0';
    utf8_from_wide(buf, device->usb_vid, sizeof(device->usb_vid));

    for (i = 0; i < 4; ++i) {
        buf[i] = pid[4 + i];
    }
    buf[4] = L'\0';
    utf8_from_wide(buf, device->usb_pid, sizeof(device->usb_pid));

    return true;
}

/* Walks up the PnP tree from a disk devnode looking for a USB ancestor. */
static usbs_bool walk_up_for_usb(DEVINST start, usbs_device_t *device)
{
    DEVINST current = start;
    int     depth;

    for (depth = 0; depth < 8; ++depth) {
        DEVINST parent;
        wchar_t id[MAX_DEVICE_ID_LEN + 1];

        if (CM_Get_Parent(&parent, current, 0) != CR_SUCCESS) {
            return false;
        }
        if (CM_Get_Device_IDW(parent, id, MAX_DEVICE_ID_LEN, 0) != CR_SUCCESS) {
            return false;
        }
        if (parse_vid_pid(id, device)) {
            return true;
        }
        current = parent;
    }
    return false;
}

/*
 * Best-effort: fills usb_vid/usb_pid for the disk carrying `disk_number`.
 * Failure is silent because identity degrades to the serial or volume GUID.
 */
static void lookup_usb_ids(usbs_u32 disk_number, usbs_device_t *device)
{
    HDEVINFO                 set;
    SP_DEVICE_INTERFACE_DATA iface;
    DWORD                    index;

    set = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_DISK, NULL, NULL,
                               DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (set == INVALID_HANDLE_VALUE) {
        return;
    }

    memset(&iface, 0, sizeof(iface));
    iface.cbSize = sizeof(iface);

    for (index = 0;
         SetupDiEnumDeviceInterfaces(set, NULL, &GUID_DEVINTERFACE_DISK,
                                     index, &iface);
         ++index) {
        PSP_DEVICE_INTERFACE_DETAIL_DATA_W detail;
        SP_DEVINFO_DATA                    devinfo;
        DWORD                              needed = 0;
        HANDLE                             disk;
        usbs_u32                           found_number = 0;
        usbs_bool                          matched = false;

        SetupDiGetDeviceInterfaceDetailW(set, &iface, NULL, 0, &needed, NULL);
        if (needed == 0) {
            continue;
        }

        detail = (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)calloc(1, needed);
        if (detail == NULL) {
            break;
        }
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

        memset(&devinfo, 0, sizeof(devinfo));
        devinfo.cbSize = sizeof(devinfo);

        if (SetupDiGetDeviceInterfaceDetailW(set, &iface, detail, needed,
                                             NULL, &devinfo)) {
            disk = open_device_zero_access(detail->DevicePath);
            if (disk != INVALID_HANDLE_VALUE) {
                if (query_disk_number(disk, &found_number) &&
                    found_number == disk_number) {
                    matched = true;
                }
                CloseHandle(disk);
            }
            if (matched) {
                walk_up_for_usb(devinfo.DevInst, device);
            }
        }

        free(detail);
        if (matched) {
            break;
        }
    }

    SetupDiDestroyDeviceInfoList(set);
}

/* --- enumeration --- */

static usbs_status_t win32_enumerate(void *ctx, usbs_device_list_t *out_list)
{
    wchar_t  volume[USBS_VOLUME_PATH_MAX];
    HANDLE   find;
    DWORD    previous_mode = 0;
    usbs_bool mode_changed;

    USBS_UNUSED(ctx);

    /* Stop Windows popping "insert a disk" dialogs for empty reader slots. */
    mode_changed = SetThreadErrorMode(SEM_FAILCRITICALERRORS, &previous_mode)
                       ? true
                       : false;

    find = FindFirstVolumeW(volume, (DWORD)USBS_ARRAY_LEN(volume));
    if (find == INVALID_HANDLE_VALUE) {
        usbs_status_t status = usbs_platform_status_from_win32(GetLastError());
        if (mode_changed) {
            SetThreadErrorMode(previous_mode, NULL);
        }
        USBS_LOG_E("FindFirstVolumeW failed: %s", usbs_status_string(status));
        return status;
    }

    do {
        usbs_device_t device;
        wchar_t       no_slash[USBS_VOLUME_PATH_MAX];
        HANDLE        handle;
        usbs_status_t push_status;

        usbs_device_init(&device);
        utf8_from_wide(volume, device.volume_path, sizeof(device.volume_path));

        fill_volume_info(volume, &device);
        fill_mount_points(volume, &device);

        wcscpy_s(no_slash, USBS_ARRAY_LEN(no_slash), volume);
        strip_trailing_slash(no_slash);

        handle = open_device_zero_access(no_slash);
        if (handle != INVALID_HANDLE_VALUE) {
            if (query_disk_number(handle, &device.disk_number)) {
                device.has_disk_number = true;
            }
            query_storage_descriptor(handle, &device);
            CloseHandle(handle);
        } else {
            USBS_LOG_D("cannot open %s: %s", device.volume_path,
                       usbs_status_string(
                           usbs_platform_status_from_win32(GetLastError())));
        }

        /* VID/PID only matters for USB devices, and the lookup is not cheap. */
        if (device.bus_type == USBS_BUS_USB && device.has_disk_number) {
            lookup_usb_ids(device.disk_number, &device);
        }

        push_status = usbs_device_list_push(out_list, &device);
        if (!usbs_ok(push_status)) {
            FindVolumeClose(find);
            if (mode_changed) {
                SetThreadErrorMode(previous_mode, NULL);
            }
            return push_status;
        }
    } while (FindNextVolumeW(find, volume, (DWORD)USBS_ARRAY_LEN(volume)));

    FindVolumeClose(find);
    if (mode_changed) {
        SetThreadErrorMode(previous_mode, NULL);
    }
    return USBS_OK;
}

usbs_device_source_t usbs_platform_device_source(void)
{
    usbs_device_source_t source;
    source.enumerate = win32_enumerate;
    source.ctx       = NULL;
    return source;
}

/* --- capability probing --- */

void usbs_capabilities_init(usbs_capabilities_t *caps)
{
    if (caps == NULL) {
        return;
    }
    memset(caps, 0, sizeof(*caps));
}

/* Probes by attempting, then closing. Access denial is a result, not an error. */
static usbs_bool can_open_for_read(const wchar_t *path)
{
    HANDLE handle = CreateFileW(path,
                                GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                OPEN_EXISTING,
                                0,
                                NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    CloseHandle(handle);
    return true;
}

/* --- cancellation --- */

static volatile LONG g_cancel_requested = 0;

static BOOL WINAPI console_control_handler(DWORD signal)
{
    switch (signal) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        InterlockedExchange(&g_cancel_requested, 1);
        return TRUE;
    default:
        return FALSE;
    }
}

usbs_status_t usbs_platform_install_cancel_handler(void)
{
    if (!SetConsoleCtrlHandler(console_control_handler, TRUE)) {
        return usbs_platform_status_from_win32(GetLastError());
    }
    return USBS_OK;
}

usbs_bool usbs_platform_cancel_requested(void)
{
    return InterlockedCompareExchange(&g_cancel_requested, 0, 0) != 0;
}

usbs_status_t usbs_platform_probe_capabilities(const usbs_device_t *device,
                                               usbs_capabilities_t *out_caps)
{
    wchar_t path[64];
    int     converted;

    if (device == NULL || out_caps == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    usbs_capabilities_init(out_caps);

    converted = MultiByteToWideChar(CP_UTF8, 0, device->volume_path, -1,
                                    path, (int)USBS_ARRAY_LEN(path));
    if (converted > 0) {
        strip_trailing_slash(path);
        out_caps->can_read_raw_volume = can_open_for_read(path);
    }

    if (device->has_disk_number) {
        wchar_t disk_path[64];
        swprintf_s(disk_path, USBS_ARRAY_LEN(disk_path),
                   L"\\\\.\\PhysicalDrive%lu", (unsigned long)device->disk_number);
        out_caps->can_read_physical_disk = can_open_for_read(disk_path);
    }

    return USBS_OK;
}

#else /* !_WIN32 */

usbs_status_t usbs_platform_status_from_win32(unsigned long win32_error)
{
    USBS_UNUSED(win32_error);
    return USBS_ERR_UNSUPPORTED;
}

usbs_device_source_t usbs_platform_device_source(void)
{
    usbs_device_source_t source;
    source.enumerate = NULL;
    source.ctx       = NULL;
    return source;
}

void usbs_capabilities_init(usbs_capabilities_t *caps)
{
    if (caps != NULL) {
        memset(caps, 0, sizeof(*caps));
    }
}

usbs_status_t usbs_platform_probe_capabilities(const usbs_device_t *device,
                                               usbs_capabilities_t *out_caps)
{
    USBS_UNUSED(device);
    usbs_capabilities_init(out_caps);
    return USBS_ERR_UNSUPPORTED;
}

usbs_status_t usbs_platform_install_cancel_handler(void)
{
    return USBS_ERR_UNSUPPORTED;
}

usbs_bool usbs_platform_cancel_requested(void)
{
    return false;
}

#endif /* _WIN32 */
