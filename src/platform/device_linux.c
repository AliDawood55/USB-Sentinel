/*
 * Linux device enumeration and capability probing, via sysfs and
 * /proc/self/mountinfo. Compiled only on Linux (ARCHITECTURE.md section
 * 21); macOS gets device_macos.c (section 21.3), and any other UNIX gets
 * device_posix_unsupported.c.
 *
 * Strategy, mirroring device_win32.c's shape and ARCHITECTURE.md section
 * 7.1's Windows strategy as closely as each platform's actual facilities
 * allow:
 *   1. /sys/class/block enumerates block devices (Windows: FindFirstVolumeW
 *      over volume GUIDs).
 *   2. Walking sysfs's own device-tree ancestry decides bus type - never
 *      /sys/block/<name>/removable, which reports "is this media
 *      removable", a materially different and independent question from
 *      "is this attached over USB" (Windows: never GetDriveType as a USB
 *      test; IOCTL_STORAGE_QUERY_PROPERTY's BusType and RemovableMedia are
 *      likewise two separate fields from the same descriptor).
 *   3. /proc/self/mountinfo supplies mount points and filesystem type
 *      (Windows: GetVolumePathNamesForVolumeNameW /
 *      GetVolumeInformationW). /dev/disk/by-label and /dev/disk/by-uuid
 *      supply the volume label and a media-presence signal for a device
 *      that is not currently mounted.
 *
 * Landed across two commits, per ARCHITECTURE.md section 21: 14b.1 was
 * block discovery and capacity only, bus_type deliberately left
 * USBS_BUS_UNKNOWN; this state adds the ancestry walk, mount info, and
 * label, completing every field 14b.1 left at its honest zeroed default.
 * Capability probing remains deliberately deferred for all of Phase 14b -
 * see usbs_platform_probe_capabilities() below.
 *
 * Testability: the real entry point (usbs_platform_device_source()) reads
 * the real "/sys" and "/proc/self/mountinfo". usbs_linux_device_source_at()
 * - not declared in any public header, the same pattern hash_match.c and
 * cmd_scan.c already use for their own test-only internal surfaces - takes
 * both roots as injectable parameters instead, so tests/test_device_linux.c
 * can run this exact algorithm against a fake tree built under a scratch
 * directory rather than against whatever disks happen to be attached to
 * the machine running the test. /dev/disk/by-label and /dev/disk/by-uuid
 * are the one exception - see find_dev_disk_match()'s own comment on why
 * those cannot be made injectable the same way, and how that gap is
 * covered instead.
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "usbsentinel/log.h"
#include "usbsentinel/path.h"
#include "usbsentinel/platform.h"

/* Local path bound for sysfs path-building, matching fs_posix.c's own
 * FS_POSIX_PATH_MAX - not shared via a header because this is this file's
 * own private concern, not part of any layering boundary.
 *
 * Must be at least PATH_MAX: realpath(path, resolved_path)'s two-argument
 * POSIX form (used below) requires the caller's buffer to be at least
 * that large, with no way for realpath() itself to check or report a
 * smaller one - the buffer is just written into up to PATH_MAX bytes.
 * "#if" rather than a plain "#define ... PATH_MAX" so this is still a
 * fixed, known constant (matching every other buffer in this file, and
 * avoiding making the value only checkable at runtime) while still
 * failing to compile, rather than silently overflowing, if some future
 * platform's PATH_MAX ever exceeded 4096. (<limits.h> is already included
 * above.) */
#if defined(PATH_MAX) && PATH_MAX > 4096
#define DEVICE_LINUX_PATH_MAX PATH_MAX
#else
#define DEVICE_LINUX_PATH_MAX 4096
#endif

/* fs_posix.c's own errno translator - not declared in any header (nothing
 * above the platform layer may see an errno), but not static either, so
 * it is linkable within usbs_platform the same way hash_match.c and
 * cmd_scan.c already expose their own test-only internal surfaces. Reused
 * here rather than duplicated for the one raw POSIX call in this file
 * (list_class_block(), below) that platform.h's own API cannot serve. */
extern usbs_status_t usbs_posix_status_from_errno(int err);

/* --- small sysfs helpers --- */

/*
 * Reads a small sysfs attribute file (a single line, at most a few hundred
 * bytes) into `out`, trimming trailing whitespace/newline. Returns
 * USBS_ERR_NOT_FOUND if the attribute does not exist - many genuinely are
 * optional (a cheap flash drive's USB descriptor commonly carries no
 * serial string at all), which is a normal, honest outcome here, not a
 * fault.
 */
static usbs_status_t read_sysfs_string(const char *path, char *out, size_t cap)
{
    usbs_file_t  *file;
    usbs_status_t status;
    size_t        total = 0;

    if (path == NULL || out == NULL || cap == 0) {
        return USBS_ERR_INVALID_ARG;
    }
    out[0] = '\0';

    status = usbs_platform_file_open_read(path, &file);
    if (!usbs_ok(status)) {
        return status;
    }

    for (;;) {
        size_t read = 0;
        if (total >= cap - 1) {
            break;
        }
        status = usbs_platform_file_read(file, out + total, cap - 1 - total, &read);
        if (!usbs_ok(status) || read == 0) {
            break;
        }
        total += read;
    }
    usbs_platform_file_close(file);
    out[total] = '\0';

    /* sysfs attributes are newline-terminated; strip trailing whitespace. */
    while (total > 0 && (unsigned char)out[total - 1] <= ' ') {
        out[--total] = '\0';
    }
    return USBS_OK;
}

/* Reads and parses a decimal sysfs integer attribute (size, removable). */
static usbs_bool read_sysfs_u64(const char *path, usbs_u64 *out)
{
    char               text[32];
    char              *end = NULL;
    unsigned long long value;

    *out = 0;
    if (!usbs_ok(read_sysfs_string(path, text, sizeof(text))) || text[0] == '\0') {
        return false;
    }
    value = strtoull(text, &end, 10);
    if (end == text) {
        return false; /* no digits parsed */
    }
    *out = (usbs_u64)value;
    return true;
}

/* Existence check for a small attribute FILE (never a directory - every
 * caller here only ever probes for "partition", which sysfs always exposes
 * as a plain file). */
static usbs_bool attr_file_exists(const char *path)
{
    usbs_file_t *file;
    if (!usbs_ok(usbs_platform_file_open_read(path, &file))) {
        return false;
    }
    usbs_platform_file_close(file);
    return true;
}

/*
 * Lists the immediate entries of "<root>/class/block" - the one place in
 * this file that genuinely must NOT use usbs_platform_dir_open()/dir_next().
 *
 * Every entry under /sys/class/block/ is itself a symlink (that is how
 * sysfs's flat "class" aggregation works: /sys/class/block/sdb1 points at
 * the device's real location under /sys/devices/...). fs_posix.c's
 * dir_next() deliberately reports a symlink AS a symlink
 * (fstatat(AT_SYMLINK_NOFOLLOW)), not as whatever it points at - that is
 * exactly the guarantee ARCHITECTURE.md section 9.3 needs for a hostile
 * scanned volume. Reused here it would report every single class/block
 * entry as "not a directory" and enumeration would silently see nothing.
 * Every OTHER directory this file lists (a disk's own real subdirectory,
 * e.g. "<root>/class/block/sdb" once opendir() has already followed that
 * one symlink) holds genuine subdirectories, not further symlinks, so
 * dir_open()/dir_next() are correct and used normally everywhere else
 * below - this is the one deliberate, narrow exception, not a reason to
 * distrust the rest of this file's use of the shared traversal API.
 *
 * Calls `on_entry(name, is_dir, ctx)` for each entry except "." and "..",
 * stopping early (without treating it as an error here) the first time
 * `on_entry` returns false - the caller's own mechanism for propagating a
 * fatal condition, such as usbs_device_list_push() running out of memory,
 * out of this loop. Raw opendir()/readdir()/stat() (stat, not lstat: this
 * is what follows the symlink, the entire reason this function exists) -
 * platform.h's directory API is deliberately not reused for this one call,
 * the same way device_win32.c uses raw Win32 calls directly rather than
 * reusing fs_win32.c's own traversal API for its own, different purposes.
 */
static usbs_status_t list_class_block(
    const char *block_dir,
    usbs_bool (*on_entry)(const char *name, usbs_bool is_dir, void *ctx),
    void *ctx)
{
    DIR *dir = opendir(block_dir);

    if (dir == NULL) {
        return usbs_posix_status_from_errno(errno);
    }

    for (;;) {
        const struct dirent *ent;
        char                 child_path[DEVICE_LINUX_PATH_MAX];
        struct stat          st;
        usbs_bool            is_dir = false;

        errno = 0;
        ent = readdir(dir);
        if (ent == NULL) {
            break; /* end of listing, or a readdir() error - either way, done */
        }
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        if (!usbs_ok(usbs_path_join(child_path, sizeof(child_path), block_dir,
                                    ent->d_name))) {
            continue; /* implausibly long name; skip rather than fail */
        }
        /* Plain stat(), which follows the symlink - the entire point of
         * this function, per the comment above. */
        if (stat(child_path, &st) == 0) {
            is_dir = S_ISDIR(st.st_mode) ? true : false;
        }
        if (!on_entry(ent->d_name, is_dir, ctx)) {
            break;
        }
    }

    closedir(dir);
    return USBS_OK;
}

/* --- partition / whole-disk detection --- */

/*
 * True if `entry_dir` (a sysfs block entry's own directory, e.g.
 * "<root>/class/block/sdb1") carries its own "partition" attribute file -
 * the sysfs signal that this entry IS a partition, not a whole disk.
 */
static usbs_bool is_partition_entry(const char *entry_dir)
{
    char path[DEVICE_LINUX_PATH_MAX];
    if (!usbs_ok(usbs_path_join(path, sizeof(path), entry_dir, "partition"))) {
        return false;
    }
    return attr_file_exists(path);
}

/*
 * True if the whole-disk entry at `entry_dir` (e.g. "<root>/class/block/sdb")
 * has partition children - meaning it is not itself directly mountable, and
 * its partitions (which separately appear as their own top-level sysfs
 * entries, e.g. "<root>/class/block/sdb1") are what should be enumerated
 * instead. An unpartitioned whole disk (a "superfloppy"-formatted USB
 * stick, filesystem directly on the disk, no partition table) has none, and
 * is itself the volume to enumerate.
 *
 * Read via the same directory iterator and file reader fs_posix.c already
 * exposes and this project already trusts for scanned volumes. Unlike a
 * scanned USB volume's own contents, sysfs is a trusted, kernel-owned
 * pseudo-filesystem, not attacker-controlled removable media - so, unlike
 * fs_posix.c's traversal, nothing here needs AT_SYMLINK_NOFOLLOW discipline;
 * that guarantee exists to keep a hostile stick's traversal from escaping
 * the volume being scanned, and no such adversary exists in sysfs.
 */
static usbs_bool disk_has_partition_children(const char *entry_dir)
{
    usbs_dir_iter_t *iter;
    usbs_dir_entry_t child;
    usbs_bool        found = false;

    if (!usbs_ok(usbs_platform_dir_open(entry_dir, &iter))) {
        return false;
    }
    while (usbs_ok(usbs_platform_dir_next(iter, &child))) {
        char child_path[DEVICE_LINUX_PATH_MAX];
        if (!child.is_directory) {
            continue;
        }
        if (usbs_ok(usbs_path_join(child_path, sizeof(child_path), entry_dir, child.name)) &&
            is_partition_entry(child_path)) {
            found = true;
            break;
        }
    }
    usbs_platform_dir_close(iter);
    return found;
}

/*
 * The sysfs directory of the WHOLE DISK that owns `entry_dir` - itself, if
 * `entry_dir` already is an unpartitioned whole disk, else its parent via
 * "<entry_dir>/..".
 *
 * Shared by fill_capacity_and_removable() ("removable" lives on the whole
 * disk, never on a partition) and the USB ancestry walk (§21.2: a
 * partition shares its whole disk's device-tree ancestry, so that is
 * where the walk must start). Not a string-manipulation trick: partition
 * naming schemes vary ("sdb1", "nvme0n1p1", "mmcblk0p1"), and hand-parsing
 * a suffix to find the parent name would need a separate rule per scheme.
 * "sdb1/.." works regardless of naming convention because "sdb1" is a
 * symlink whose target is nested inside "sdb"'s own directory in the real
 * device tree, and POSIX path resolution follows a symlink component
 * fully before applying a trailing ".." - the same idiom standard tools
 * like lsblk rely on.
 */
static usbs_status_t whole_disk_dir(const char *entry_dir, usbs_bool own_partition,
                                    char *out, size_t cap)
{
    if (own_partition) {
        return usbs_path_join(out, cap, entry_dir, "..");
    }
    if (snprintf(out, cap, "%s", entry_dir) >= (int)cap) {
        return USBS_ERR_NO_MEMORY;
    }
    return USBS_OK;
}

/* --- per-device data collection --- */

/*
 * Fills capacity_bytes and removable_media for one enumerated entry.
 * `own_partition` is what is_partition_entry() already determined for this
 * entry, passed in rather than recomputed.
 *
 * "size" is always in 512-byte sectors regardless of the device's actual
 * physical or logical sector size - a stable part of the kernel's sysfs
 * block ABI, not an assumption specific to any one device.
 */
static void fill_capacity_and_removable(const char *entry_dir, usbs_bool own_partition,
                                        usbs_device_t *device)
{
    char     size_path[DEVICE_LINUX_PATH_MAX];
    char     disk_dir[DEVICE_LINUX_PATH_MAX];
    char     removable_path[DEVICE_LINUX_PATH_MAX];
    usbs_u64 sectors   = 0;
    usbs_u64 removable = 0;

    if (usbs_ok(usbs_path_join(size_path, sizeof(size_path), entry_dir, "size")) &&
        read_sysfs_u64(size_path, &sectors)) {
        device->capacity_bytes = sectors * 512u;
    }

    if (!usbs_ok(whole_disk_dir(entry_dir, own_partition, disk_dir, sizeof(disk_dir)))) {
        return;
    }
    if (usbs_ok(usbs_path_join(removable_path, sizeof(removable_path), disk_dir,
                               "removable")) &&
        read_sysfs_u64(removable_path, &removable)) {
        device->removable_media = (removable != 0);
    }
}

/* --- USB ancestry walk (bus_type, vendor/product/serial/VID-PID) --- */

/*
 * Truncates `path` (already absolute and symlink-free - every caller here
 * passes a realpath()-resolved string) to its parent directory, in place.
 * A plain string operation is correct only because of that precondition:
 * unlike "<dir>/..", which lets the kernel resolve any remaining symlinks
 * or ".." components, this assumes there are none left to resolve.
 * Returns false once `path` has no parent left above "/" - the walk's
 * natural termination, not an error.
 */
static usbs_bool truncate_to_parent(char *path)
{
    char *slash = strrchr(path, '/');
    if (slash == NULL || slash == path) {
        return false;
    }
    *slash = '\0';
    return true;
}

/*
 * Reads the symlink at "<dir>/subsystem" and returns just its final path
 * component (e.g. "usb", "scsi", "pci", "nvme") - sysfs's own answer to
 * "what kind of bus object is this", independent of the device's name or
 * position in the tree. Returns an empty string if "<dir>/subsystem" is
 * not a symlink at all (some sysfs levels have none).
 */
static void read_subsystem_name(const char *dir, char *out, size_t cap)
{
    char    link_path[DEVICE_LINUX_PATH_MAX];
    char    target[DEVICE_LINUX_PATH_MAX];
    ssize_t written;
    const char *base;

    out[0] = '\0';
    if (!usbs_ok(usbs_path_join(link_path, sizeof(link_path), dir, "subsystem"))) {
        return;
    }
    written = readlink(link_path, target, sizeof(target) - 1);
    if (written <= 0) {
        return;
    }
    target[written] = '\0';

    base = strrchr(target, '/');
    base = (base != NULL) ? base + 1 : target;
    snprintf(out, cap, "%s", base);
}

/*
 * Walks up from `start_dir` (the whole disk's own "device" symlink,
 * already resolved to an absolute, symlink-free real path by the caller)
 * looking for the USB device node that actually carries idVendor/idProduct
 * - not merely something with subsystem "usb", which a USB *interface*
 * node also reports. A mass-storage device's real tree typically looks
 * like ".../usb1/1-2/1-2:1.0/host3/target3:0:0/3:0:0:0": "target3:0:0"
 * etc. report subsystem "scsi", walked past; "1-2:1.0" is the interface
 * (subsystem "usb", no idVendor - walked past); "1-2" is the actual USB
 * device (subsystem "usb", has idVendor - the match).
 *
 * Bounded to a generous 12 levels (device_win32.c's own walk_up_for_usb()
 * bounds itself to 8 PnP-tree levels for the same reason: sysfs has no
 * cycles by construction, but bounding a walk over data this file did not
 * create is cheap insurance, not paranoia).
 *
 * On a match, fills bus_type, usb_vid/usb_pid (as lowercase 4-hex-digit
 * strings - sysfs's idVendor/idProduct already are exactly that, unlike
 * Windows's VID_xxxx/PID_xxxx substring extraction, so no reformatting is
 * needed), vendor/product/serial (each independently optional - a cheap
 * flash drive's descriptor commonly omits one or more).
 *
 * bus_type stays USBS_BUS_UNKNOWN, and no other field is touched, if no
 * USB ancestor is found. Deliberately does NOT attempt to distinguish
 * SATA/NVMe/SCSI for a non-USB device (ARCHITECTURE.md section 21.2): the
 * CLI's own filtering only ever needs "is this USB", and libata's SATA-
 * via-SCSI translation makes a reliable SATA/SCSI distinction from sysfs
 * alone a materially bigger undertaking than this phase's scope.
 */
static void usb_walk_up(const char *start_dir, usbs_device_t *device)
{
    char current[DEVICE_LINUX_PATH_MAX];
    int  depth;

    snprintf(current, sizeof(current), "%s", start_dir);

    for (depth = 0; depth < 12; ++depth) {
        char subsystem[64];
        char id_path[DEVICE_LINUX_PATH_MAX];

        read_subsystem_name(current, subsystem, sizeof(subsystem));
        if (strcmp(subsystem, "usb") == 0 &&
            usbs_ok(usbs_path_join(id_path, sizeof(id_path), current, "idVendor")) &&
            attr_file_exists(id_path)) {
            char text[16];

            device->bus_type = USBS_BUS_USB;

            /* "%.4s" (a precision, not a width): idVendor/idProduct are
             * always exactly 4 hex digits per the USB spec, and this also
             * gives the compiler a static bound on how much of `text` can
             * be copied into a 5-byte destination - it cannot otherwise
             * know that read_sysfs_string()'s output happens to fit. */
            if (usbs_ok(read_sysfs_string(id_path, text, sizeof(text)))) {
                snprintf(device->usb_vid, sizeof(device->usb_vid), "%.4s", text);
            }
            if (usbs_ok(usbs_path_join(id_path, sizeof(id_path), current, "idProduct")) &&
                usbs_ok(read_sysfs_string(id_path, text, sizeof(text)))) {
                snprintf(device->usb_pid, sizeof(device->usb_pid), "%.4s", text);
            }
            if (usbs_ok(usbs_path_join(id_path, sizeof(id_path), current, "manufacturer"))) {
                read_sysfs_string(id_path, device->vendor, sizeof(device->vendor));
            }
            if (usbs_ok(usbs_path_join(id_path, sizeof(id_path), current, "product"))) {
                read_sysfs_string(id_path, device->product, sizeof(device->product));
            }
            if (usbs_ok(usbs_path_join(id_path, sizeof(id_path), current, "serial"))) {
                read_sysfs_string(id_path, device->serial, sizeof(device->serial));
            }
            return;
        }

        if (!truncate_to_parent(current)) {
            return; /* reached the top with no USB ancestor found */
        }
    }
}

/* --- /proc/self/mountinfo: mount points, volume_path, filesystem --- */

/*
 * Un-escapes mountinfo's octal byte-escapes (\040 space, \011 tab, \134
 * backslash, \012 newline - the only characters mountinfo escapes, since
 * they would otherwise be indistinguishable from field separators or
 * embedded newlines in the file's own line-oriented format) in place.
 * A malformed "\" not followed by three octal digits is passed through
 * literally rather than mis-parsed - defensive against a mountinfo line
 * this file did not anticipate, not an expected case.
 */
static void unescape_mountinfo_field(char *field)
{
    char  *read_ptr  = field;
    char  *write_ptr = field;

    while (*read_ptr != '\0') {
        if (read_ptr[0] == '\\' &&
            read_ptr[1] >= '0' && read_ptr[1] <= '7' &&
            read_ptr[2] >= '0' && read_ptr[2] <= '7' &&
            read_ptr[3] >= '0' && read_ptr[3] <= '7') {
            int value = (read_ptr[1] - '0') * 64 +
                        (read_ptr[2] - '0') * 8 +
                        (read_ptr[3] - '0');
            *write_ptr++ = (char)value;
            read_ptr += 4;
        } else {
            *write_ptr++ = *read_ptr++;
        }
    }
    *write_ptr = '\0';
}

/*
 * Un-escapes udev's own "\xHH" hex-byte encoding - used for /dev/disk/
 * by-label, by-uuid, ... symlink names - which is a DIFFERENT scheme
 * from mountinfo's octal "\NNN" above and must not be confused with it:
 * udev replaces any byte outside its safe set (notably space) this way,
 * so a "UBUNTU 22_0" label becomes the symlink name "UBUNTU\x2022_0".
 *
 * find_dev_disk_match() below previously ran unescape_mountinfo_field()
 * (the octal decoder) on these names instead, which cannot decode a
 * "\xHH" sequence and so left it completely untouched - confirmed
 * against a real beta tester's own Ubuntu install USB stick, whose
 * label displayed as the literal, undecoded "UBUNTU\x2022_0" rather
 * than "UBUNTU 22_0". A malformed "\x" not followed by two hex digits
 * is passed through literally, matching unescape_mountinfo_field()'s
 * own defensive stance on a malformed escape.
 *
 * Not declared static: exposed the same way usbs_linux_device_source_at()
 * is (no public header entry, just an extern prototype in
 * tests/test_device_linux.c) purely so that file can exercise this pure
 * string function directly - unlike find_dev_disk_match()'s real
 * matching branch, decoding a string needs no real device node or
 * privilege at all.
 */
void usbs_linux_unescape_udev_name(char *name)
{
    char *read_ptr  = name;
    char *write_ptr = name;

    while (*read_ptr != '\0') {
        if (read_ptr[0] == '\\' && read_ptr[1] == 'x' &&
            isxdigit((unsigned char)read_ptr[2]) &&
            isxdigit((unsigned char)read_ptr[3])) {
            char hex[3] = { read_ptr[2], read_ptr[3], '\0' };
            *write_ptr++ = (char)strtol(hex, NULL, 16);
            read_ptr += 4;
        } else {
            *write_ptr++ = *read_ptr++;
        }
    }
    *write_ptr = '\0';
}

/*
 * True if `source` - mountinfo's own tenth field, the string the mount
 * was made "from" (e.g. "/dev/sdb1") - resolves to a block device whose
 * real st_rdev is `major_num:minor_num`. Matched via stat()+major()/
 * minor(), the same pattern find_dev_disk_match() below already uses for
 * /dev/disk/by-label and by-uuid, and for the same underlying reason:
 * comparing resolved device identity rather than trusting any particular
 * spelling.
 *
 * This exists because mountinfo's field 3 (major:minor) is NOT always
 * this device's own identity: for a FUSE-backed filesystem - ntfs-3g or
 * exfat-fuse, both routinely what udisks2 auto-mounts a Windows-
 * formatted USB stick with on a real Ubuntu desktop, confirmed by a
 * beta tester's real ADATA drive going entirely unmatched - the kernel
 * reports the FUSE character device's own major:minor there, not the
 * backing block device's, so field 3 can never equal `dev_id` even
 * though the mount genuinely is this device. Field 10 (source) is not
 * affected: FUSE mount helpers still record the real underlying device
 * node there, so falling back to it here recovers exactly the cases
 * field-3 matching alone misses, without weakening the field-3 match
 * (tried first, in the loop below) for every ordinary in-kernel
 * filesystem (ext4, vfat, the in-kernel exfat/ntfs3 drivers).
 */
static usbs_bool source_matches_dev_id(const char *source, unsigned major_num, unsigned minor_num)
{
    struct stat st;

    if (source == NULL || source[0] != '/') {
        return false; /* not a device path (e.g. "none", a bind-mount tag) */
    }
    if (stat(source, &st) != 0 || !S_ISBLK(st.st_mode)) {
        return false;
    }
    return major(st.st_rdev) == major_num && minor(st.st_rdev) == minor_num;
}

/*
 * Fills mount_points[]/volume_path/filesystem from every /proc/self/
 * mountinfo line whose major:minor (field 3) matches `dev_id` (this
 * device's own "<entry_dir>/dev" attribute, e.g. "8:17") - the same
 * major:minor identity sysfs and the kernel's mount table both use, so
 * this needs no assumption about /dev/<name> naming conventions at all -
 * or, failing that, whose source field (see source_matches_dev_id()
 * above) resolves to the same device, which covers FUSE-backed mounts
 * that field 3 alone cannot.
 *
 * volume_path is the FIRST match, with a trailing separator (device.h's
 * convention). Deliberately not implemented: capability to read
 * filesystem/label for a device that is NOT currently mounted - see this
 * file's header comment on the platform asymmetry this creates
 * (ARCHITECTURE.md section 21.2). free_bytes is filled via statvfs() on
 * volume_path once it is known, since GetDiskFreeSpaceExW's Windows-side
 * trick of working without a mount point has no POSIX equivalent.
 *
 * Read in exactly ONE read() call, not accumulated across a loop of
 * several: /proc/pid/mountinfo is kernel seq_file content, generated on
 * demand rather than stored, and a multi-call accumulation loop is not
 * guaranteed a consistent snapshot if the mount table changes between two
 * of those calls (a mount or unmount racing the read, anywhere on the
 * system, not necessarily on the volume being examined) - a documented
 * seq_file limitation, not a defect in this file's own logic. A real
 * example was hit and diagnosed during Phase 14b.2's own development
 * (ARCHITECTURE.md section 21.2): a heavily mount-churning host produced
 * exactly this - lines interleaved from two different reads, silently
 * matching nothing. Every real tool that reads this file (mount, findmnt,
 * systemd) does the same single-large-read - the industry answer to a
 * known kernel-interface property, not a project-specific workaround.
 *
 * A single call generously sized at 256 KiB (a busy desktop's mountinfo
 * is a few KiB at most) still cannot rule out sub-syscall interleaving in
 * principle, but reduces the exposure from "any gap between N separate
 * syscalls" to "the kernel's own single seq_file generation pass" - as
 * good as user space reading this interface can practically do. Heap, not
 * stack, matching this project's established practice for a buffer this
 * size (TASKS.md's Phase 12 notes: hash_match.c's own read buffer moved
 * to heap for exactly this reason).
 */
static void fill_mount_info(const char *mountinfo_path, const char *dev_id,
                            usbs_device_t *device)
{
    enum { MOUNTINFO_CAP = 256 * 1024 };
    usbs_file_t *file;
    char        *buf;
    size_t       total = 0;
    char        *line;
    char        *saveptr = NULL;
    unsigned     dev_major = 0, dev_minor = 0;
    usbs_bool    have_dev_major_minor = (sscanf(dev_id, "%u:%u", &dev_major, &dev_minor) == 2);

    if (!usbs_ok(usbs_platform_file_open_read(mountinfo_path, &file))) {
        return;
    }
    buf = (char *)malloc(MOUNTINFO_CAP);
    if (buf == NULL) {
        usbs_platform_file_close(file);
        return;
    }
    if (!usbs_ok(usbs_platform_file_read(file, buf, MOUNTINFO_CAP - 1, &total))) {
        total = 0;
    }
    usbs_platform_file_close(file);
    buf[total] = '\0';

    /*
     * v1.2.2-debug DIAGNOSTIC LOGGING addition (2nd round): settles which
     * of two candidate mechanisms is actually happening for a beta report
     * where parsing consistently stops after the same mountinfo line
     * across every independently-read device, on real Ubuntu hardware
     * only - a genuine short read() (this single call not returning the
     * whole file, which would mean `total` lands short of the file's real
     * size with the tail visibly missing) versus the GUI process simply
     * observing a different /proc/self/mountinfo than the CLI does (a
     * different launch context / mount namespace, in which case this read
     * is already complete and correct for what THIS process can see, and
     * looping or growing the buffer would fix nothing).
     *
     * `total == MOUNTINFO_CAP - 1` (the buffer arriving completely full)
     * is the one signal that would actually indicate a short read against
     * a bigger file - not a hunch about kernel internals, a direct
     * measurement. The last captured bytes are logged too: ending cleanly
     * on a full, well-formed line is what a real, complete read looks
     * like; ending mid-line is what a genuine truncation looks like. Not
     * removed together with the rest of the v1.2.2-debug instrumentation.
     */
    {
        size_t tail_start = (total > 120) ? total - 120 : 0;
        USBS_LOG_I("[debug] fill_mount_info(dev_id='%s'): read %zu byte(s) of a %d-byte "
                  "buffer (%s); tail: \"%s\"",
                  dev_id, total, MOUNTINFO_CAP - 1,
                  (total == (size_t)(MOUNTINFO_CAP - 1))
                      ? "BUFFER COMPLETELY FULL - file may be larger, this read is suspect"
                      : "buffer not full - this read captured everything it could get",
                  buf + tail_start);
    }

    for (line = strtok_r(buf, "\n", &saveptr); line != NULL;
         line = strtok_r(NULL, "\n", &saveptr)) {
        /* Fields: id parent major:minor root mountpoint options [tags...] - fstype source superopts */
        char *fields[6];
        int   count;
        char *line_saveptr = NULL;
        char *dash;

        /* The optional-fields run (zero or more tag entries) is why this
         * cannot be a fixed sscanf() format: it is terminated by a literal
         * "-" token whose position varies. Split off exactly the first 6
         * whitespace-delimited fields, then find the "-" separator in
         * what remains and take exactly the fstype/source that follow it -
         * per `man 5 proc_pid_mountinfo`.
         *
         * Written as this exact shape rather than a `for` loop whose
         * increment clause both advances and tests `count`: that shape
         * calls strtok_r() one extra time on the iteration that fails the
         * count check, silently consuming the very "-" token the code
         * right after this loop needs to see next - a real, found bug
         * (ARCHITECTURE.md section 21.2), not a hypothetical one. Calling
         * strtok_r() exactly six times, no more, is what makes
         * line_saveptr's position after this loop reliable. */
        for (count = 0; count < 6; ++count) {
            char *tok = strtok_r((count == 0) ? line : NULL, " ", &line_saveptr);
            if (tok == NULL) {
                break;
            }
            fields[count] = tok;
        }
        if (count < 6) {
            continue; /* malformed line; skip rather than misparse */
        }

        /* Skip the optional-fields run up to and including the "-", then
         * read fstype/source unconditionally - needed even when field 3
         * does not match dev_id, since that alone is not yet a verdict:
         * a FUSE-backed mount (ntfs-3g, exfat-fuse) fails this compare
         * for every line of its own mount, and can only be recognized
         * below via source_matches_dev_id() on the source field read
         * here. */
        dash = strtok_r(NULL, " ", &line_saveptr);
        while (dash != NULL && strcmp(dash, "-") != 0) {
            dash = strtok_r(NULL, " ", &line_saveptr);
        }
        if (dash == NULL) {
            continue; /* no "-" found; malformed, skip */
        }

        {
            char *fstype = strtok_r(NULL, " ", &line_saveptr);
            char *source = strtok_r(NULL, " ", &line_saveptr);
            char  mount_point[DEVICE_LINUX_PATH_MAX];
            char  source_buf[DEVICE_LINUX_PATH_MAX];
            usbs_bool is_match = (strcmp(fields[2], dev_id) == 0);
            usbs_bool matched_via_fallback = false;

            if (!is_match && have_dev_major_minor && source != NULL) {
                snprintf(source_buf, sizeof(source_buf), "%s", source);
                unescape_mountinfo_field(source_buf);
                is_match = source_matches_dev_id(source_buf, dev_major, dev_minor);
                matched_via_fallback = is_match;
            }

            /* v1.2.2-debug DIAGNOSTIC LOGGING - see ARCHITECTURE.md section
             * 22.10. Every mountinfo line considered for this dev_id, the
             * major:minor actually found in field[2], whether that direct
             * compare matched, and - since it did not - whether the
             * FUSE-style source_matches_dev_id() fallback fired instead.
             * Temporary; to be removed before a real v1.2.2. */
            USBS_LOG_I("[debug] mountinfo line for dev_id='%s': major:minor='%s' "
                      "mountpoint='%s' source='%s' direct_match=%d fallback_match=%d",
                      dev_id, fields[2], fields[4], source ? source : "(none)",
                      (usbs_bool)(strcmp(fields[2], dev_id) == 0), matched_via_fallback);

            if (!is_match) {
                continue; /* not this device, by either identity */
            }

            snprintf(mount_point, sizeof(mount_point), "%s", fields[4]);
            unescape_mountinfo_field(mount_point);

            if (device->mount_point_count < USBS_MOUNT_POINTS_MAX) {
                snprintf(device->mount_points[device->mount_point_count],
                         USBS_MOUNT_POINT_MAX, "%s", mount_point);
                ++device->mount_point_count;
            }
            /* volume_path must be something usbs_platform_dir_open() can
             * actually walk - a real, found case for why this check
             * exists: a container's mountinfo can legitimately bind-mount
             * this device onto a plain FILE (e.g. /etc/resolv.conf, one
             * real match observed running this exact code), which
             * "first match wins" would otherwise have picked as the scan
             * root. mount_points[] still records every match, matching
             * Windows's own GetVolumePathNamesForVolumeNameW, which
             * likewise does not filter by directory-ness - only
             * volume_path's own stricter contract (ARCHITECTURE.md
             * section 7.2: "the scan root") requires this extra check. */
            if (device->volume_path[0] == '\0') {
                struct stat mount_point_stat;
                if (stat(mount_point, &mount_point_stat) == 0 &&
                    S_ISDIR(mount_point_stat.st_mode)) {
                    usbs_path_join(device->volume_path, sizeof(device->volume_path),
                                   mount_point, "");
                }
            }
            if (fstype != NULL && device->filesystem[0] == '\0') {
                snprintf(device->filesystem, sizeof(device->filesystem), "%s", fstype);
            }
        }
    }

    free(buf);

    if (device->volume_path[0] != '\0') {
        struct statvfs vfs;
        if (statvfs(device->volume_path, &vfs) == 0) {
            device->free_bytes = (usbs_u64)vfs.f_bavail * (usbs_u64)vfs.f_frsize;
        }
    }
}

/* --- /dev/disk/by-label and /dev/disk/by-uuid: label and media presence --- */

/*
 * Scans udev's "/dev/disk/<by_dir>" (e.g. "by-label", "by-uuid") for a
 * symlink whose target - a real device node - matches `dev_id` ("8:17"),
 * matched via stat()+major()/minor() on the resolved target rather than
 * any assumption about the target's own spelling (udev's naming for it
 * can differ from any sysfs entry name). Returns true if a match was
 * found, and - when `out_name` is non-NULL - copies the matching entry's
 * own name (the label or UUID string itself, un-escaped via
 * usbs_linux_unescape_udev_name() - udev's own "\xHH" scheme, NOT
 * mountinfo's octal "\NNN") into it.
 *
 * Deliberately NOT reachable through the injectable sysfs root
 * (usbs_linux_device_source_at()): "/dev/disk" is a separate tree from
 * "/sys", populated by udev from real block devices, and a fixture cannot
 * construct a fake entry here without a real device node (mknod), which
 * needs privilege a test should not require. tests/test_device_linux.c
 * therefore does not exercise this function's matching branch at all;
 * test_platform.c's test_live_enumeration() exercises it for real, against
 * whatever the CI runner's own disks actually have (verifying at least
 * that it does not crash and falls back cleanly when there is no match),
 * and real positive-match verification - "does this actually find MY usb
 * stick's real label" - is exactly the kind of check ARCHITECTURE.md
 * section 21.4's beta-tester template asks for, not something CI can
 * prove on its own (section 21.2).
 */
static usbs_bool find_dev_disk_match(const char *by_dir, const char *dev_id,
                                     char *out_name, size_t out_cap)
{
    unsigned             major_num, minor_num;
    char                 by_path[DEVICE_LINUX_PATH_MAX];
    DIR                 *dir;
    const struct dirent *ent;
    usbs_bool            found = false;

    if (sscanf(dev_id, "%u:%u", &major_num, &minor_num) != 2) {
        return false;
    }
    if (!usbs_ok(usbs_path_join(by_path, sizeof(by_path), "/dev/disk", by_dir))) {
        return false;
    }

    dir = opendir(by_path);
    if (dir == NULL) {
        return false; /* no udev, or nothing to match yet - an honest "no" */
    }

    while (!found && (ent = readdir(dir)) != NULL) {
        char        link_path[DEVICE_LINUX_PATH_MAX];
        struct stat st;

        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        if (!usbs_ok(usbs_path_join(link_path, sizeof(link_path), by_path, ent->d_name))) {
            continue;
        }
        /* Plain stat(): follows the symlink to the real device node. */
        if (stat(link_path, &st) != 0 || !S_ISBLK(st.st_mode)) {
            continue;
        }
        if (major(st.st_rdev) == major_num && minor(st.st_rdev) == minor_num) {
            found = true;
            if (out_name != NULL) {
                snprintf(out_name, out_cap, "%s", ent->d_name);
                usbs_linux_unescape_udev_name(out_name); /* udev's "\xHH", not mountinfo's octal */
            }
        }
    }
    closedir(dir);
    return found;
}

/* --- enumeration --- */

typedef struct block_entry_ctx {
    const char         *block_dir;
    const char         *mountinfo_path;
    usbs_device_list_t *out_list;
    usbs_status_t       status; /* set on a fatal error; USBS_OK otherwise */
} block_entry_ctx_t;

/* list_class_block()'s callback for one "<block_dir>/<name>" entry. Returns
 * false only to stop the listing early (a fatal, not-recoverable condition,
 * recorded in ctx->status); an entry that is simply not a volume (a
 * whole disk with partition children) is handled by `continue`-equivalent
 * behaviour - returning true - not by stopping. */
static usbs_bool handle_block_entry(const char *name, usbs_bool is_dir, void *ctx_ptr)
{
    block_entry_ctx_t *ctx = (block_entry_ctx_t *)ctx_ptr;
    usbs_device_t      device;
    char               entry_dir[DEVICE_LINUX_PATH_MAX];
    char               dev_id_path[DEVICE_LINUX_PATH_MAX];
    char               dev_id[32];
    char               disk_dir[DEVICE_LINUX_PATH_MAX];
    usbs_bool          own_partition;
    usbs_bool          have_dev_id;
    usbs_status_t      push_status;

    /* v1.2.2-debug DIAGNOSTIC LOGGING - see ARCHITECTURE.md section 22.10.
     * Temporary, for one specific real-hardware investigation; to be
     * removed before an actual v1.2.2 ships. USBS_LOG_I so it prints by
     * default (main.c's threshold is USBS_LOG_INFO) with no extra flag
     * the tester would need to remember. */
    USBS_LOG_I("[debug] list_class_block entry: name='%s' stat_is_dir=%d", name, is_dir);

    if (!is_dir) {
        return true; /* every real block entry resolves to a directory */
    }
    if (!usbs_ok(usbs_path_join(entry_dir, sizeof(entry_dir), ctx->block_dir, name))) {
        return true; /* implausibly long name; skip rather than fail the scan */
    }

    own_partition = is_partition_entry(entry_dir);
    USBS_LOG_I("[debug] '%s': is_partition_entry=%d", name, own_partition);
    if (!own_partition && disk_has_partition_children(entry_dir)) {
        /* A whole disk with partitions: its partitions are enumerated
         * separately as their own top-level entries, so this entry itself
         * is not a volume. */
        USBS_LOG_I("[debug] '%s': whole disk WITH partition children - SKIPPED", name);
        return true;
    }
    USBS_LOG_I("[debug] '%s': INCLUDED (own_partition=%d, has_partition_children=%s)",
              name, own_partition, own_partition ? "n/a" : "false");

    usbs_device_init(&device);
    fill_capacity_and_removable(entry_dir, own_partition, &device);

    /* The USB ancestry walk starts from the WHOLE DISK's own "device"
     * symlink - a partition shares its whole disk's device-tree ancestry,
     * it has none of its own. realpath() both follows every symlink
     * component (the class-aggregation symlink AND the disk's own
     * "device" symlink) and canonicalizes away every ".." in one step,
     * giving usb_walk_up() a clean absolute path to walk up from.
     *
     * A caller-supplied buffer, not realpath(path, NULL)'s glibc/BSD
     * extension of having it malloc one for the caller: that form's
     * runtime behaviour is a separate question from whether realpath()'s
     * prototype is merely visible (a real, already-hit bug here - see
     * ARCHITECTURE.md section 21.2 - was a silently mismatched implicit
     * declaration truncating this very pointer to 32 bits). A fixed
     * DEVICE_LINUX_PATH_MAX buffer, matching every other path in this
     * file, needs no malloc-failure handling and depends on nothing but
     * the POSIX-mandated two-argument form. */
    if (usbs_ok(whole_disk_dir(entry_dir, own_partition, disk_dir, sizeof(disk_dir)))) {
        char device_link[DEVICE_LINUX_PATH_MAX];
        char resolved[DEVICE_LINUX_PATH_MAX];

        if (usbs_ok(usbs_path_join(device_link, sizeof(device_link), disk_dir, "device")) &&
            realpath(device_link, resolved) != NULL) {
            usb_walk_up(resolved, &device);
        }
    }

    /* "dev" (major:minor) is this entry's own identity in the kernel's
     * mount table and in udev's by-label/by-uuid symlinks - read once,
     * used for both. */
    have_dev_id = usbs_ok(usbs_path_join(dev_id_path, sizeof(dev_id_path), entry_dir, "dev")) &&
                  usbs_ok(read_sysfs_string(dev_id_path, dev_id, sizeof(dev_id)));
    /* v1.2.2-debug DIAGNOSTIC LOGGING */
    USBS_LOG_I("[debug] '%s': dev_id_path='%s' have_dev_id=%d dev_id='%s'",
              name, dev_id_path, have_dev_id, have_dev_id ? dev_id : "(none)");
    if (have_dev_id) {
        fill_mount_info(ctx->mountinfo_path, dev_id, &device);
        find_dev_disk_match("by-label", dev_id, device.label, sizeof(device.label));
        device.media_present = (device.mount_point_count > 0) ||
                               find_dev_disk_match("by-uuid", dev_id, NULL, 0);
    }

    /* v1.2.2-debug DIAGNOSTIC LOGGING: the final usbs_device_t fields,
     * exactly as they are about to be pushed into the enumerated list -
     * this is the ground truth the tester's report is missing. */
    USBS_LOG_I("[debug] '%s': FINAL bus_type=%s capacity_bytes=%llu free_bytes=%llu "
              "mount_point_count=%u volume_path='%s' filesystem='%s' label='%s' "
              "media_present=%d usb_vid='%s' usb_pid='%s'",
              name, usbs_bus_type_string(device.bus_type),
              (unsigned long long)device.capacity_bytes,
              (unsigned long long)device.free_bytes,
              device.mount_point_count, device.volume_path, device.filesystem,
              device.label, device.media_present, device.usb_vid, device.usb_pid);
    {
        usbs_u32 mp_i;
        for (mp_i = 0; mp_i < device.mount_point_count; ++mp_i) {
            USBS_LOG_I("[debug] '%s': mount_points[%u] = '%s'", name, mp_i,
                      device.mount_points[mp_i]);
        }
    }

    push_status = usbs_device_list_push(ctx->out_list, &device);
    if (!usbs_ok(push_status)) {
        ctx->status = push_status;
        return false;
    }
    return true;
}

/* The two injectable roots, kept as their own small type distinct from
 * block_entry_ctx_t (above) even though both are "this function's ctx
 * struct" - overloading one struct's fields with two different meanings
 * at two different points in the call chain is exactly the kind of thing
 * that reads clearly today and confuses the next reader (or the next
 * edit) later. */
typedef struct linux_roots {
    const char *sysfs_root;
    const char *mountinfo_path;
} linux_roots_t;

static usbs_status_t linux_enumerate(void *ctx_ptr, usbs_device_list_t *out_list)
{
    const linux_roots_t *roots = (const linux_roots_t *)ctx_ptr;
    char                  block_dir[DEVICE_LINUX_PATH_MAX];
    block_entry_ctx_t     entry_ctx;
    usbs_status_t         status;

    if (roots == NULL || roots->sysfs_root == NULL || roots->mountinfo_path == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (!usbs_ok(usbs_path_join(block_dir, sizeof(block_dir), roots->sysfs_root,
                               "class/block"))) {
        return USBS_ERR_INVALID_ARG;
    }

    entry_ctx.block_dir      = block_dir;
    entry_ctx.mountinfo_path = roots->mountinfo_path;
    entry_ctx.out_list       = out_list;
    entry_ctx.status         = USBS_OK;

    status = list_class_block(block_dir, handle_block_entry, &entry_ctx);
    if (!usbs_ok(status)) {
        /* A host with no /sys/class/block at all (not a real Linux kernel,
         * or a sysfs that failed to mount) is a genuine enumeration
         * failure, not "zero devices" - the same honest distinction
         * usbs_device_enumerate() already draws for a NULL enumerate. */
        USBS_LOG_E("cannot open %s: %s", block_dir, usbs_status_string(status));
        return status;
    }
    return entry_ctx.status;
}

/*
 * Not declared in any public header - the same pattern hash_match.c and
 * cmd_scan.c already use for their own test-only internal surfaces. Lets
 * tests/test_device_linux.c point this exact algorithm at a fake sysfs
 * tree and a fake mountinfo file; usbs_platform_device_source() below is
 * the only production caller, always with the two real paths.
 *
 * A single MUTABLE STATIC linux_roots_t, not one heap-allocated or owned
 * by the caller: safe here specifically because this project's
 * concurrency model is single-threaded (ARCHITECTURE.md section 9.3) and,
 * in every call site in this codebase - production and test alike - a
 * device source is always constructed and its one enumerate() call
 * completed before anything constructs another. Two sources are never
 * alive simultaneously, so overwriting this static on each call is
 * indistinguishable from allocating a fresh one.
 */
usbs_device_source_t usbs_linux_device_source_at(const char *sysfs_root,
                                                 const char *mountinfo_path)
{
    static linux_roots_t roots;
    usbs_device_source_t source;

    roots.sysfs_root     = sysfs_root;
    roots.mountinfo_path = mountinfo_path;

    source.enumerate = linux_enumerate;
    source.ctx       = &roots;
    return source;
}

usbs_device_source_t usbs_platform_device_source(void)
{
    return usbs_linux_device_source_at("/sys", "/proc/self/mountinfo");
}

/* --- capability probing (deferred) --- */

/*
 * Not yet implemented in Phase 14b: probing "can this process read the raw
 * volume / whole disk" needs a device-node path (/dev/<name>) this file
 * does not yet track anywhere in usbs_device_t, and Phase 14b's agreed scope
 * (ARCHITECTURE.md section 21.1) is enumeration - devices/scan working at
 * all - not capability probing, which every caller already degrades
 * gracefully without (scanner.c logs a warning and leaves capabilities at
 * their zeroed, conservative default; cmd_devices.c prints "unavailable").
 * A genuine, deliberately small scoping decision, recorded rather than
 * silently left unaddressed.
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
