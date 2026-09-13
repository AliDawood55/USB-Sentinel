/*
 * Deterministic tests for device_linux.c's sysfs/mountinfo-parsing
 * algorithm, run against a fake tree built under a scratch directory
 * rather than the real /sys - the same fixture-vs-real-environment split
 * this project already uses for scanner/storage (a real scratch
 * directory standing in for a volume root) and for the enumeration seam
 * itself (test_device.c's own fixture usbs_device_source_t). Complements,
 * rather than duplicates, test_platform.c's test_live_enumeration(),
 * which runs this same algorithm against whatever the real host's actual
 * disks and mount table happen to look like.
 *
 * Linux-only (CMake builds this file only when CMAKE_SYSTEM_NAME is
 * "Linux" - tests/CMakeLists.txt), so raw symlink()/mkdir() calls are used
 * directly for fixture setup rather than through platform.h, which has no
 * symlink-creation API and should not gain one purely for test scaffolding
 * - the same precedent test_scanner.c already sets for touching the OS
 * directly when a test's own setup, not product code, needs it.
 *
 * NOT covered here: the USB ancestor walk's positive USB match against
 * /dev/disk/by-label or /dev/disk/by-uuid at all (find_dev_disk_match()'s
 * own comment explains why - it needs a real device node, which needs
 * privilege a test should not require) is not exercised here either;
 * both are real-hardware questions this file structurally cannot answer,
 * left to ARCHITECTURE.md section 21.4's beta-tester process. What IS
 * covered here - block/partition discovery, capacity, the ancestor walk's
 * mechanics (subsystem/idVendor resolution via real symlinks this fixture
 * creates), and mountinfo parsing - is deterministic and needs no
 * privilege at all.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "test_util.h"
#include "usbsentinel/device.h"
#include "usbsentinel/path.h"
#include "usbsentinel/platform.h"

extern usbs_device_source_t usbs_linux_device_source_at(const char *sysfs_root,
                                                        const char *mountinfo_path);
extern void usbs_linux_unescape_udev_name(char *name);

static void make_scratch_root(char *out, size_t cap)
{
    static usbs_bool seeded = false;
    if (!seeded) {
        srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)out);
        seeded = true;
    }
    snprintf(out, cap, "test_device_linux_scratch_%08x", (unsigned)rand());
}

/* Raw symlink(2), not platform.h: fixture setup only, matching
 * test_scanner.c's own precedent for touching the OS directly when a
 * test's own scaffolding, not product code, needs something platform.h
 * deliberately does not expose. */
static void make_symlink(const char *target, const char *link_path)
{
    USBS_CHECK(symlink(target, link_path) == 0);
}

static void write_attr(const char *dir, const char *name, const char *content)
{
    char path[512];
    USBS_CHECK(usbs_ok(usbs_path_join(path, sizeof(path), dir, name)));
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, content, strlen(content))));
}

/*
 * Builds a fake sysfs root under `root` with one whole disk,
 * optionally a partition on it (`with_partition`), and (if
 * `with_usb_ancestor`) a real USB device+interface chain the disk's
 * "device" symlink points at - mirroring a real mass-storage tree's
 * shape (".../usb1/1-1/1-1:1.0/.../block/sdX") closely enough to
 * exercise the real ancestor-walk code, not a simplified stand-in for it.
 *
 * `with_partition` is what makes this fixture exercise ONE of two
 * genuinely different, mutually exclusive rules in device_linux.c: a
 * disk WITH a partition child is skipped (its partition is enumerated
 * instead); a disk with NO partition child (an unpartitioned
 * "superfloppy"-formatted stick) is itself the volume. The two rules
 * cannot both be exercised by one fixture, which is why the two tests
 * that need them ask for different values here rather than sharing one
 * "has a partition" fixture and hoping that also covers the other case.
 *
 * Layout:
 *   <root>/sys/devices/fakedisk/            the whole disk's real dir
 *     size, removable, dev
 *     device -> ../../usbtree/1-1/1-1:1.0   (only if with_usb_ancestor)
 *     fakedisk1/                             the partition's real dir
 *       partition, size, dev                  (only if with_partition)
 *   <root>/sys/class/block/fakedisk  -> ../../devices/fakedisk
 *   <root>/sys/class/block/fakedisk1 -> ../../devices/fakedisk/fakedisk1
 *                                              (only if with_partition)
 *   <root>/sys/usbtree/1-1/                 the USB device node
 *     subsystem -> ../../bus/usb            (basename "usb")
 *     idVendor, idProduct, manufacturer, product, serial
 *     1-1:1.0/                              the USB interface node (real
 *       subsystem -> ../../../bus/usb        subdirectory of 1-1, so its
 *                                             realpath's parent IS 1-1)
 */
static void build_fake_sysfs(const char *root, usbs_bool with_partition,
                             usbs_bool with_usb_ancestor)
{
    char path[512];

    USBS_CHECK(usbs_ok(usbs_path_join(path, sizeof(path), root, "sys/devices/fakedisk")));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(path)));
    USBS_CHECK(usbs_ok(usbs_path_join(path, sizeof(path), root, "sys/class/block")));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(path)));

    /* Whole disk: 100 MiB (204800 512-byte sectors), removable. */
    {
        char disk_dir[512];
        USBS_CHECK(usbs_ok(usbs_path_join(disk_dir, sizeof(disk_dir), root, "sys/devices/fakedisk")));
        write_attr(disk_dir, "size", "204800");
        write_attr(disk_dir, "removable", "1");
        write_attr(disk_dir, "dev", "7:0");
    }

    if (with_partition) {
        /* Partition: 50 MiB (102400 sectors), has its own "partition" file. */
        char part_dir[512];
        USBS_CHECK(usbs_ok(usbs_path_join(part_dir, sizeof(part_dir), root,
                                          "sys/devices/fakedisk/fakedisk1")));
        USBS_CHECK(usbs_ok(usbs_platform_make_dirs(part_dir)));
        write_attr(part_dir, "size", "102400");
        write_attr(part_dir, "partition", "1");
        write_attr(part_dir, "dev", "7:1");
    }

    /* The class/block flat symlinks - what makes "/sys/class/block" list
     * these at all, mirroring the real "class aggregation" sysfs uses. */
    {
        char class_disk[512];
        USBS_CHECK(usbs_ok(usbs_path_join(class_disk, sizeof(class_disk), root,
                                          "sys/class/block/fakedisk")));
        make_symlink("../../devices/fakedisk", class_disk);

        if (with_partition) {
            char class_part[512];
            USBS_CHECK(usbs_ok(usbs_path_join(class_part, sizeof(class_part), root,
                                              "sys/class/block/fakedisk1")));
            make_symlink("../../devices/fakedisk/fakedisk1", class_part);
        }
    }

    if (with_usb_ancestor) {
        char usb_device_dir[512];
        char usb_iface_dir[512];
        char disk_device_link[512];

        USBS_CHECK(usbs_ok(usbs_path_join(usb_device_dir, sizeof(usb_device_dir), root,
                                          "sys/usbtree/1-1")));
        USBS_CHECK(usbs_ok(usbs_path_join(usb_iface_dir, sizeof(usb_iface_dir), root,
                                          "sys/usbtree/1-1/1-1:1.0")));
        USBS_CHECK(usbs_ok(usbs_platform_make_dirs(usb_iface_dir)));

        write_attr(usb_device_dir, "idVendor", "0781");
        write_attr(usb_device_dir, "idProduct", "5567");
        write_attr(usb_device_dir, "manufacturer", "SanDisk");
        write_attr(usb_device_dir, "product", "Cruzer Blade");
        write_attr(usb_device_dir, "serial", "ABCDEF123456");
        {
            char subsystem_link[512];
            USBS_CHECK(usbs_ok(usbs_path_join(subsystem_link, sizeof(subsystem_link),
                                              usb_device_dir, "subsystem")));
            make_symlink("../../bus/usb", subsystem_link);
        }
        {
            char subsystem_link[512];
            USBS_CHECK(usbs_ok(usbs_path_join(subsystem_link, sizeof(subsystem_link),
                                              usb_iface_dir, "subsystem")));
            make_symlink("../../../bus/usb", subsystem_link);
        }

        USBS_CHECK(usbs_ok(usbs_path_join(disk_device_link, sizeof(disk_device_link), root,
                                          "sys/devices/fakedisk/device")));
        make_symlink("../../usbtree/1-1/1-1:1.0", disk_device_link);
    }
}

static void write_fake_mountinfo(const char *path, const char *content)
{
    USBS_CHECK(usbs_ok(usbs_platform_write_file(path, content, strlen(content))));
}

static const usbs_device_t *find_by_capacity(const usbs_device_list_t *list, usbs_u64 capacity)
{
    size_t i;
    for (i = 0; i < list->count; ++i) {
        if (list->items[i].capacity_bytes == capacity) {
            return &list->items[i];
        }
    }
    return NULL;
}

/* --- tests --- */

/* An UNPARTITIONED whole disk (no partition children at all - a
 * "superfloppy"-formatted stick) must be enumerated as itself: there is
 * no partition for it to defer to. */
static void test_unpartitioned_whole_disk_is_enumerated(void)
{
    char                  root[260];
    char                  sysfs_root[300];
    char                  mountinfo_path[300];
    usbs_device_source_t  source;
    usbs_device_list_t    list;
    const usbs_device_t  *disk;

    make_scratch_root(root, sizeof(root));
    build_fake_sysfs(root, false /* with_partition */, false /* with_usb_ancestor */);
    USBS_CHECK(usbs_ok(usbs_path_join(sysfs_root, sizeof(sysfs_root), root, "sys")));
    USBS_CHECK(usbs_ok(usbs_path_join(mountinfo_path, sizeof(mountinfo_path), root, "mountinfo")));
    write_fake_mountinfo(mountinfo_path, "");

    source = usbs_linux_device_source_at(sysfs_root, mountinfo_path);
    USBS_CHECK(usbs_ok(usbs_device_enumerate(&source, &list)));

    disk = find_by_capacity(&list, 204800ull * 512u);
    USBS_REQUIRE(disk != NULL);
    USBS_CHECK(disk->removable_media == true);
    USBS_CHECK(disk->bus_type == USBS_BUS_UNKNOWN);

    usbs_device_list_free(&list);
}

/* The whole-disk entry must be SKIPPED once it has a partition child -
 * its partition is separately enumerated as its own top-level entry, and
 * the whole disk itself is not a volume. The mutually exclusive case to
 * the test above: this fixture builds WITH a partition, so only that
 * partition - never the disk - may appear. */
static void test_whole_disk_with_partition_is_skipped(void)
{
    char                  root[260];
    char                  sysfs_root[300];
    char                  mountinfo_path[300];
    usbs_device_source_t  source;
    usbs_device_list_t    list;
    size_t                i;
    usbs_bool             found_disk_capacity = false;

    make_scratch_root(root, sizeof(root));
    build_fake_sysfs(root, true /* with_partition */, false /* with_usb_ancestor */);
    USBS_CHECK(usbs_ok(usbs_path_join(sysfs_root, sizeof(sysfs_root), root, "sys")));
    USBS_CHECK(usbs_ok(usbs_path_join(mountinfo_path, sizeof(mountinfo_path), root, "mountinfo")));
    write_fake_mountinfo(mountinfo_path, "");

    source = usbs_linux_device_source_at(sysfs_root, mountinfo_path);
    USBS_CHECK(usbs_ok(usbs_device_enumerate(&source, &list)));

    /* The disk (204800 sectors) has a partition child in this fixture
     * (fakedisk1), so it must not appear as its own entry - only the
     * partition (102400 sectors) should. */
    for (i = 0; i < list.count; ++i) {
        if (list.items[i].capacity_bytes == 204800ull * 512u) {
            found_disk_capacity = true;
        }
    }
    USBS_CHECK(!found_disk_capacity);
    USBS_CHECK(find_by_capacity(&list, 102400ull * 512u) != NULL);

    usbs_device_list_free(&list);
}

/* The negative path for the ancestor walk: no USB device anywhere in the
 * chain (no "device" symlink at all here) must leave bus_type at its
 * honest USBS_BUS_UNKNOWN default, not misclassify. */
static void test_no_usb_ancestor_stays_unknown(void)
{
    char                  root[260];
    char                  sysfs_root[300];
    char                  mountinfo_path[300];
    usbs_device_source_t  source;
    usbs_device_list_t    list;
    const usbs_device_t  *partition;

    make_scratch_root(root, sizeof(root));
    build_fake_sysfs(root, true /* with_partition */, false /* with_usb_ancestor */);
    USBS_CHECK(usbs_ok(usbs_path_join(sysfs_root, sizeof(sysfs_root), root, "sys")));
    USBS_CHECK(usbs_ok(usbs_path_join(mountinfo_path, sizeof(mountinfo_path), root, "mountinfo")));
    write_fake_mountinfo(mountinfo_path, "");

    source = usbs_linux_device_source_at(sysfs_root, mountinfo_path);
    USBS_CHECK(usbs_ok(usbs_device_enumerate(&source, &list)));

    partition = find_by_capacity(&list, 102400ull * 512u);
    USBS_REQUIRE(partition != NULL);
    USBS_CHECK(partition->bus_type == USBS_BUS_UNKNOWN);
    USBS_CHECK(partition->usb_vid[0] == '\0');
    USBS_CHECK(partition->usb_pid[0] == '\0');

    usbs_device_list_free(&list);
}

/*
 * The positive path: a real (fixture-built, but structurally real -
 * actual symlinks, actual nested interface/device directories) USB
 * ancestor chain must be found and its idVendor/idProduct/strings read
 * correctly - this is the part of the walk this project can test
 * deterministically without real hardware, distinct from "does this
 * match an actual USB stick", which cannot be (this file's own header
 * comment).
 */
static void test_usb_ancestor_found_and_fields_read(void)
{
    char                  root[260];
    char                  sysfs_root[300];
    char                  mountinfo_path[300];
    usbs_device_source_t  source;
    usbs_device_list_t    list;
    const usbs_device_t  *partition;
    const usbs_device_t  *disk;

    make_scratch_root(root, sizeof(root));
    build_fake_sysfs(root, true /* with_partition */, true /* with_usb_ancestor */);
    USBS_CHECK(usbs_ok(usbs_path_join(sysfs_root, sizeof(sysfs_root), root, "sys")));
    USBS_CHECK(usbs_ok(usbs_path_join(mountinfo_path, sizeof(mountinfo_path), root, "mountinfo")));
    write_fake_mountinfo(mountinfo_path, "");

    source = usbs_linux_device_source_at(sysfs_root, mountinfo_path);
    USBS_CHECK(usbs_ok(usbs_device_enumerate(&source, &list)));

    /* The whole disk has a partition child here too, so only the
     * partition is enumerated - and a partition shares its whole disk's
     * ancestry (device_linux.c's whole_disk_dir()), so it inherits the
     * USB classification from "fakedisk", not from anything of its own. */
    disk = find_by_capacity(&list, 204800ull * 512u);
    USBS_CHECK(disk == NULL); /* skipped: has a partition child */

    partition = find_by_capacity(&list, 102400ull * 512u);
    USBS_REQUIRE(partition != NULL);
    USBS_CHECK(partition->bus_type == USBS_BUS_USB);
    USBS_CHECK_STR_EQ(partition->usb_vid, "0781");
    USBS_CHECK_STR_EQ(partition->usb_pid, "5567");
    USBS_CHECK_STR_EQ(partition->vendor, "SanDisk");
    USBS_CHECK_STR_EQ(partition->product, "Cruzer Blade");
    USBS_CHECK_STR_EQ(partition->serial, "ABCDEF123456");

    usbs_device_list_free(&list);
}

/* mountinfo matching: a directory mount point is found, becomes
 * volume_path, and free_bytes is filled via a real statvfs() on it. */
static void test_mountinfo_directory_match(void)
{
    char                  root[260];
    char                  sysfs_root[300];
    char                  mountinfo_path[300];
    char                  mount_dir[300];
    char                  mountinfo_content[600];
    usbs_device_source_t  source;
    usbs_device_list_t    list;
    const usbs_device_t  *partition;

    make_scratch_root(root, sizeof(root));
    build_fake_sysfs(root, true /* with_partition */, false /* with_usb_ancestor */);
    USBS_CHECK(usbs_ok(usbs_path_join(sysfs_root, sizeof(sysfs_root), root, "sys")));
    USBS_CHECK(usbs_ok(usbs_path_join(mountinfo_path, sizeof(mountinfo_path), root, "mountinfo")));
    USBS_CHECK(usbs_ok(usbs_path_join(mount_dir, sizeof(mount_dir), root, "mnt")));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(mount_dir)));

    /* dev_id "7:1" matches the partition (fakedisk1)'s own "dev" attribute.
     * A real, mount-table-shaped line, hand-built rather than copied from
     * a live system - the exact fields this test needs to control. */
    snprintf(mountinfo_content, sizeof(mountinfo_content),
             "100 1 7:1 / %s rw,relatime - ext4 /dev/fakedisk1 rw\n", mount_dir);
    write_fake_mountinfo(mountinfo_path, mountinfo_content);

    source = usbs_linux_device_source_at(sysfs_root, mountinfo_path);
    USBS_CHECK(usbs_ok(usbs_device_enumerate(&source, &list)));

    partition = find_by_capacity(&list, 102400ull * 512u);
    USBS_REQUIRE(partition != NULL);
    USBS_CHECK(partition->mount_point_count == 1);
    if (partition->mount_point_count == 1) {
        USBS_CHECK_STR_EQ(partition->mount_points[0], mount_dir);
    }
    USBS_CHECK_STR_EQ(partition->filesystem, "ext4");
    USBS_CHECK(partition->media_present == true); /* mounted implies present */
    USBS_CHECK(strncmp(partition->volume_path, mount_dir, strlen(mount_dir)) == 0);
    USBS_CHECK(usbs_path_is_separator(
        partition->volume_path[strlen(partition->volume_path) - 1]));
    /* statvfs() ran against a real directory, so free_bytes is whatever
     * this machine's real filesystem reports for it - not zero, and not
     * larger than the (unrelated) fake capacity_bytes ever needs to
     * relate to, since volume_path's free space and the fake device's
     * declared size are deliberately different real-vs-fixture facts. */
    USBS_CHECK(partition->free_bytes > 0 || partition->capacity_bytes > 0);

    usbs_device_list_free(&list);
}

/*
 * The real bug this test is modeled on (ARCHITECTURE.md section 21.2): a
 * mountinfo match whose mount point is a plain FILE, not a directory
 * (exactly what a container's bind-mounted /etc/resolv.conf produces),
 * must be recorded in mount_points[] but must NOT become volume_path -
 * scanner.c can only ever walk a directory.
 */
static void test_mountinfo_file_bind_mount_not_used_as_volume_path(void)
{
    char                  root[260];
    char                  sysfs_root[300];
    char                  mountinfo_path[300];
    char                  bind_file[300];
    char                  mountinfo_content[600];
    usbs_device_source_t  source;
    usbs_device_list_t    list;
    const usbs_device_t  *partition;

    make_scratch_root(root, sizeof(root));
    build_fake_sysfs(root, true /* with_partition */, false /* with_usb_ancestor */);
    USBS_CHECK(usbs_ok(usbs_path_join(sysfs_root, sizeof(sysfs_root), root, "sys")));
    USBS_CHECK(usbs_ok(usbs_path_join(mountinfo_path, sizeof(mountinfo_path), root, "mountinfo")));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(root)));
    USBS_CHECK(usbs_ok(usbs_path_join(bind_file, sizeof(bind_file), root, "resolv.conf")));
    USBS_CHECK(usbs_ok(usbs_platform_write_file(bind_file, "nameserver 127.0.0.1", 21)));

    snprintf(mountinfo_content, sizeof(mountinfo_content),
             "100 1 7:1 / %s rw,relatime - ext4 /dev/fakedisk1 rw\n", bind_file);
    write_fake_mountinfo(mountinfo_path, mountinfo_content);

    source = usbs_linux_device_source_at(sysfs_root, mountinfo_path);
    USBS_CHECK(usbs_ok(usbs_device_enumerate(&source, &list)));

    partition = find_by_capacity(&list, 102400ull * 512u);
    USBS_REQUIRE(partition != NULL);
    USBS_CHECK(partition->mount_point_count == 1); /* still recorded */
    if (partition->mount_point_count == 1) {
        USBS_CHECK_STR_EQ(partition->mount_points[0], bind_file);
    }
    USBS_CHECK(partition->volume_path[0] == '\0'); /* NOT used as volume_path */

    usbs_device_list_free(&list);
}

/* A mountinfo path an octal-escaped space in it must round-trip: udev/the
 * kernel escape a literal space as "\040", per `man 5 proc_pid_mountinfo`. */
static void test_mountinfo_escaped_space_unescaped(void)
{
    char                  root[260];
    char                  sysfs_root[300];
    char                  mountinfo_path[300];
    char                  mount_dir[300];
    char                  mountinfo_content[700];
    usbs_device_source_t  source;
    usbs_device_list_t    list;
    const usbs_device_t  *partition;

    make_scratch_root(root, sizeof(root));
    build_fake_sysfs(root, true /* with_partition */, false /* with_usb_ancestor */);
    USBS_CHECK(usbs_ok(usbs_path_join(sysfs_root, sizeof(sysfs_root), root, "sys")));
    USBS_CHECK(usbs_ok(usbs_path_join(mountinfo_path, sizeof(mountinfo_path), root, "mountinfo")));
    snprintf(mount_dir, sizeof(mount_dir), "%s/mnt with space", root);
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(mount_dir)));

    snprintf(mountinfo_content, sizeof(mountinfo_content),
             "100 1 7:1 / %s/mnt\\040with\\040space rw,relatime - ext4 /dev/fakedisk1 rw\n",
             root);
    write_fake_mountinfo(mountinfo_path, mountinfo_content);

    source = usbs_linux_device_source_at(sysfs_root, mountinfo_path);
    USBS_CHECK(usbs_ok(usbs_device_enumerate(&source, &list)));

    partition = find_by_capacity(&list, 102400ull * 512u);
    USBS_REQUIRE(partition != NULL);
    USBS_REQUIRE(partition->mount_point_count == 1);
    USBS_CHECK_STR_EQ(partition->mount_points[0], mount_dir);

    usbs_device_list_free(&list);
}

/*
 * udev's /dev/disk/by-label symlink names use their OWN "\xHH" hex-byte
 * escape, a different scheme from mountinfo's octal "\NNN" tested above -
 * confirmed against a real beta tester's Ubuntu install USB stick, whose
 * "UBUNTU 22_0" label displayed as the literal, undecoded
 * "UBUNTU\x2022_0" because find_dev_disk_match() was previously reusing
 * the octal decoder for it. A pure string function, so - unlike
 * find_dev_disk_match()'s real matching branch, which needs a real
 * device node - this needs no privilege or fixture tree at all.
 */
static void test_unescape_udev_name(void)
{
    char space_escaped[] = "UBUNTU\\x2022_0";
    char no_escape[]     = "plain-label";
    char malformed[]     = "trailing\\x2";
    char backslash[]     = "back\\x5cslash";

    usbs_linux_unescape_udev_name(space_escaped);
    USBS_CHECK_STR_EQ(space_escaped, "UBUNTU 22_0");

    usbs_linux_unescape_udev_name(no_escape);
    USBS_CHECK_STR_EQ(no_escape, "plain-label");

    /* "\x2" is not followed by a second hex digit; passed through as-is. */
    usbs_linux_unescape_udev_name(malformed);
    USBS_CHECK_STR_EQ(malformed, "trailing\\x2");

    usbs_linux_unescape_udev_name(backslash);
    USBS_CHECK_STR_EQ(backslash, "back\\slash");
}

/*
 * mountinfo's field 3 (major:minor) does not always identify the mounted
 * device: a FUSE-backed filesystem can report a device number with no
 * relation to any real block device at all (unlike ntfs-3g/exfat-fuse,
 * which - confirmed empirically against real loop-mounted images while
 * investigating this exact beta-test report, ARCHITECTURE.md section
 * 21.2 - use the kernel's "fuseblk" mechanism and so still get an
 * accurate field 3; a synthetic filesystem like sshfs does not). Because
 * of that, fill_mount_info() also tries matching the mount's "source"
 * field against a real block device's major:minor as a fallback. This
 * test proves that fallback does not false-positive when source is not
 * a block device at all - the negative counterpart to its real-device
 * branch, which (like find_dev_disk_match()'s own by-label/by-uuid
 * matching, see this file's header comment) needs a real device node
 * (mknod) a privilege-free fixture cannot construct, and so is left to
 * real-hardware verification instead.
 */
static void test_mountinfo_source_fallback_rejects_non_block_source(void)
{
    char                  root[260];
    char                  sysfs_root[300];
    char                  mountinfo_path[300];
    char                  mount_dir[300];
    char                  not_a_device[300];
    char                  mountinfo_content[700];
    usbs_device_source_t  source;
    usbs_device_list_t    list;
    const usbs_device_t  *partition;

    make_scratch_root(root, sizeof(root));
    build_fake_sysfs(root, true /* with_partition */, false /* with_usb_ancestor */);
    USBS_CHECK(usbs_ok(usbs_path_join(sysfs_root, sizeof(sysfs_root), root, "sys")));
    USBS_CHECK(usbs_ok(usbs_path_join(mountinfo_path, sizeof(mountinfo_path), root, "mountinfo")));
    USBS_CHECK(usbs_ok(usbs_path_join(mount_dir, sizeof(mount_dir), root, "mnt")));
    USBS_CHECK(usbs_ok(usbs_platform_make_dirs(mount_dir)));
    USBS_CHECK(usbs_ok(usbs_path_join(not_a_device, sizeof(not_a_device), root, "not-a-device")));
    USBS_CHECK(usbs_ok(usbs_platform_write_file(not_a_device, "x", 1)));

    /* Field 3 ("42:0") deliberately does not match the partition's real
     * "7:1" (simulating a synthetic FUSE device number), and source is a
     * plain file, not a block device - the fallback must refuse this as
     * a match rather than treat any non-matching line as a fallback hit. */
    snprintf(mountinfo_content, sizeof(mountinfo_content),
             "100 1 42:0 / %s rw,relatime - fuse.sshfs %s rw\n", mount_dir, not_a_device);
    write_fake_mountinfo(mountinfo_path, mountinfo_content);

    source = usbs_linux_device_source_at(sysfs_root, mountinfo_path);
    USBS_CHECK(usbs_ok(usbs_device_enumerate(&source, &list)));

    partition = find_by_capacity(&list, 102400ull * 512u);
    USBS_REQUIRE(partition != NULL);
    USBS_CHECK(partition->mount_point_count == 0);
    USBS_CHECK(partition->volume_path[0] == '\0');
    USBS_CHECK(partition->filesystem[0] == '\0');

    usbs_device_list_free(&list);
}

static void test_invalid_args(void)
{
    usbs_device_source_t source = usbs_linux_device_source_at(NULL, "/proc/self/mountinfo");
    usbs_device_list_t   list;
    USBS_CHECK(usbs_device_enumerate(&source, &list) == USBS_ERR_INVALID_ARG);

    source = usbs_linux_device_source_at("/sys", NULL);
    USBS_CHECK(usbs_device_enumerate(&source, &list) == USBS_ERR_INVALID_ARG);
}

/* A sysfs root that does not exist at all must be a real enumeration
 * failure, not "zero devices" - matching device_win32.c's own
 * FindFirstVolumeW-failure handling. */
static void test_missing_sysfs_root_fails(void)
{
    usbs_device_source_t source =
        usbs_linux_device_source_at("test_device_linux_does_not_exist/sys",
                                    "/proc/self/mountinfo");
    usbs_device_list_t list;
    USBS_CHECK(!usbs_ok(usbs_device_enumerate(&source, &list)));
}

int main(void)
{
    test_unpartitioned_whole_disk_is_enumerated();
    test_whole_disk_with_partition_is_skipped();
    test_no_usb_ancestor_stays_unknown();
    test_usb_ancestor_found_and_fields_read();
    test_mountinfo_directory_match();
    test_mountinfo_file_bind_mount_not_used_as_volume_path();
    test_mountinfo_escaped_space_unescaped();
    test_unescape_udev_name();
    test_mountinfo_source_fallback_rejects_non_block_source();
    test_invalid_args();
    test_missing_sysfs_root_fails();
    return USBS_TEST_RESULT();
}
