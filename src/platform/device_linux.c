/*
 * Linux device enumeration and capability probing, via sysfs and
 * /proc/self/mountinfo. Compiled only on Linux (ARCHITECTURE.md section
 * 20.12); macOS gets device_macos.c, and any other UNIX gets
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
 *      GetVolumeInformationW).
 *
 * PHASE 14b.1 SCOPE - this commit deliberately implements only block
 * discovery and capacity. bus_type stays USBS_BUS_UNKNOWN, and
 * media_present/mount_points/filesystem/label all stay at
 * usbs_device_init()'s zeroed defaults - honestly incomplete rather than
 * guessed, completed in 14b.2 (ARCHITECTURE.md section 20.12). Because
 * bus_type is never USB yet, no device from this step can look "scannable"
 * to cmd_scan.c/cmd_devices.c's existing bus_type == USBS_BUS_USB filters -
 * this step is safely inert from the CLI's perspective until 14b.2 lands.
 *
 * Testability: the real entry point (usbs_platform_device_source()) reads
 * the real "/sys". usbs_linux_device_source_at() - not declared in any
 * public header, the same pattern hash_match.c and cmd_scan.c already use
 * for their own test-only internal surfaces - takes an injectable sysfs
 * root instead, so tests/test_device_linux.c can run this exact algorithm
 * against a fake sysfs tree built under a scratch directory rather than
 * against whatever disks happen to be attached to the machine running the
 * test.
 */
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "usbsentinel/log.h"
#include "usbsentinel/path.h"
#include "usbsentinel/platform.h"

/* Local path bound for sysfs path-building, matching fs_posix.c's own
 * FS_POSIX_PATH_MAX - not shared via a header because this is this file's
 * own private concern, not part of any layering boundary. */
#define DEVICE_LINUX_PATH_MAX 4096

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

/* --- per-device data collection (Phase 14b.1 scope) --- */

/*
 * Fills capacity_bytes and removable_media for one enumerated entry.
 * `own_partition` is what is_partition_entry() already determined for this
 * entry, passed in rather than recomputed.
 *
 * "size" is always in 512-byte sectors regardless of the device's actual
 * physical or logical sector size - a stable part of the kernel's sysfs
 * block ABI, not an assumption specific to any one device.
 *
 * "removable" lives on the WHOLE DISK, never on a partition itself: for a
 * partition entry, "<entry_dir>/../removable" reaches it. This is not a
 * string-manipulation trick (partition naming schemes vary - "sdb1",
 * "nvme0n1p1", "mmcblk0p1" - and hand-parsing a suffix to find the parent
 * name would need a separate rule per scheme): "sdb1" is a symlink whose
 * target is nested inside "sdb"'s own directory in the real device tree,
 * and POSIX path resolution follows a symlink component fully before
 * applying a trailing ".." - so this reaches the true parent regardless of
 * naming convention, the same idiom standard tools like lsblk rely on.
 */
static void fill_capacity_and_removable(const char *entry_dir, usbs_bool own_partition,
                                        usbs_device_t *device)
{
    char     size_path[DEVICE_LINUX_PATH_MAX];
    char     removable_dir[DEVICE_LINUX_PATH_MAX];
    char     removable_path[DEVICE_LINUX_PATH_MAX];
    usbs_u64 sectors   = 0;
    usbs_u64 removable = 0;

    if (usbs_ok(usbs_path_join(size_path, sizeof(size_path), entry_dir, "size")) &&
        read_sysfs_u64(size_path, &sectors)) {
        device->capacity_bytes = sectors * 512u;
    }

    if (own_partition) {
        if (!usbs_ok(usbs_path_join(removable_dir, sizeof(removable_dir), entry_dir, ".."))) {
            return;
        }
    } else {
        snprintf(removable_dir, sizeof(removable_dir), "%s", entry_dir);
    }
    if (usbs_ok(usbs_path_join(removable_path, sizeof(removable_path), removable_dir,
                               "removable")) &&
        read_sysfs_u64(removable_path, &removable)) {
        device->removable_media = (removable != 0);
    }
}

/* --- enumeration --- */

typedef struct block_entry_ctx {
    const char         *block_dir;
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
    usbs_bool          own_partition;
    usbs_status_t      push_status;

    if (!is_dir) {
        return true; /* every real block entry resolves to a directory */
    }
    if (!usbs_ok(usbs_path_join(entry_dir, sizeof(entry_dir), ctx->block_dir, name))) {
        return true; /* implausibly long name; skip rather than fail the scan */
    }

    own_partition = is_partition_entry(entry_dir);
    if (!own_partition && disk_has_partition_children(entry_dir)) {
        /* A whole disk with partitions: its partitions are enumerated
         * separately as their own top-level entries, so this entry itself
         * is not a volume. */
        return true;
    }

    usbs_device_init(&device);
    fill_capacity_and_removable(entry_dir, own_partition, &device);
    /* bus_type, media_present, mount_points, filesystem, label: Phase 14b.2
     * (ARCHITECTURE.md section 20.12). Left at usbs_device_init()'s zeroed/
     * USBS_BUS_UNKNOWN defaults here - honestly incomplete, not guessed. */

    push_status = usbs_device_list_push(ctx->out_list, &device);
    if (!usbs_ok(push_status)) {
        ctx->status = push_status;
        return false;
    }
    return true;
}

/*
 * `ctx` is the sysfs root itself (a "const char *" cast to "void *"), not a
 * wrapping struct - 14b.1 needs no other injectable state. Whether it points
 * at a string literal ("/sys", the production default) or a test's own
 * scratch-path buffer, its lifetime only needs to cover this one call:
 * usbs_device_source_t is always constructed and consumed together, in the
 * same scope, by every caller in this codebase (cmd_scan.c, cmd_devices.c,
 * and the tests below).
 */
static usbs_status_t linux_enumerate(void *ctx, usbs_device_list_t *out_list)
{
    const char        *sysfs_root = (const char *)ctx;
    char               block_dir[DEVICE_LINUX_PATH_MAX];
    block_entry_ctx_t  entry_ctx;
    usbs_status_t      status;

    if (sysfs_root == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (!usbs_ok(usbs_path_join(block_dir, sizeof(block_dir), sysfs_root,
                               "class/block"))) {
        return USBS_ERR_INVALID_ARG;
    }

    entry_ctx.block_dir = block_dir;
    entry_ctx.out_list  = out_list;
    entry_ctx.status    = USBS_OK;

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
 * tree; usbs_platform_device_source() below is the only production caller,
 * always with the real "/sys".
 *
 * `sysfs_root` becomes the returned source's ctx directly (see
 * linux_enumerate()'s own comment on why no wrapping struct or static
 * storage is needed here): it must stay valid for as long as the returned
 * source is used, which - for every caller in this codebase - is always
 * "until the immediately following usbs_device_enumerate() call returns",
 * in the same scope.
 */
usbs_device_source_t usbs_linux_device_source_at(const char *sysfs_root)
{
    usbs_device_source_t source;
    source.enumerate = linux_enumerate;
    source.ctx       = (void *)sysfs_root;
    return source;
}

usbs_device_source_t usbs_platform_device_source(void)
{
    return usbs_linux_device_source_at("/sys");
}

/* --- capability probing (deferred) --- */

/*
 * Not yet implemented in Phase 14b: probing "can this process read the raw
 * volume / whole disk" needs a device-node path (/dev/<name>) this file
 * does not yet track anywhere in usbs_device_t, and Phase 14b's agreed scope
 * (ARCHITECTURE.md section 20.12) is enumeration - devices/scan working at
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
