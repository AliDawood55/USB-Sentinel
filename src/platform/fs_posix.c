/*
 * POSIX half of the platform module: directory traversal, read-only file
 * access, and the local data store's own writes.
 *
 * The counterpart to fs_win32.c, selected by CMake rather than by #ifdef
 * inside one file (ARCHITECTURE.md section 20.5). Everything here is plain
 * POSIX.1-2008 - opendir/readdir, fstatat, open/read, mkdir, rename, unlink -
 * with no third-party dependency, matching the platform layer's existing
 * stance on Windows.
 *
 * Paths in and out are UTF-8, as platform.h requires. On Windows that costs
 * a UTF-16 conversion at every boundary; here it costs a validation pass,
 * for the inverse reason - see sanitize_utf8() below.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "usbsentinel/log.h"
#include "usbsentinel/platform.h"

/*
 * Local path bound for the one function that has to split a path into
 * components. PATH_MAX on Linux, and deliberately a local constant rather
 * than storage.h's USBS_STORE_PATH_MAX: platform sits below storage in the
 * layering (ARCHITECTURE.md section 2) and must not reach up into it.
 */
#define FS_POSIX_PATH_MAX 4096

/* --- errno translation --- */

/*
 * The POSIX counterpart to usbs_platform_status_from_win32(). Not exposed in
 * platform.h: nothing above the platform layer may see an errno, and unlike
 * the Win32 version there is no test that needs to reach it.
 */
usbs_status_t usbs_posix_status_from_errno(int err)
{
    switch (err) {
    case 0:
        return USBS_OK;
    case EACCES:
    case EPERM:
    case EROFS:
        return USBS_ERR_ACCESS_DENIED;
    case ENOENT:
    case ENOTDIR:
    case ENXIO:
    case ENODEV:
        return USBS_ERR_NOT_FOUND;
    case ENOMEM:
        return USBS_ERR_NO_MEMORY;
    case EINVAL:
    case ENAMETOOLONG:
    case ELOOP:
        return USBS_ERR_INVALID_ARG;
    case ENOTSUP:
#if defined(EOPNOTSUPP) && EOPNOTSUPP != ENOTSUP
    case EOPNOTSUPP:
#endif
        return USBS_ERR_UNSUPPORTED;
    case EIO:
    case EBUSY:
    case ETIMEDOUT:
        return USBS_ERR_IO;
    default:
        return USBS_ERR_INTERNAL;
    }
}

/* --- UTF-8 sanitisation --- */

/*
 * Length of the valid UTF-8 sequence starting at `s`, or 0 if it is not one.
 *
 * Rejects the encodings that are structurally well-formed but not valid
 * UTF-8, because each is a known way to smuggle something past a naive
 * decoder: overlong forms (a "/" encoded as two bytes), UTF-16 surrogate
 * halves (U+D800..U+DFFF, which have no UTF-8 representation), and anything
 * above U+10FFFF.
 */
static size_t utf8_sequence_length(const unsigned char *s, size_t remaining)
{
    unsigned char c = s[0];

    if (c < 0x80u) {
        return 1;
    }
    if ((c & 0xE0u) == 0xC0u) {
        if (remaining < 2 || (s[1] & 0xC0u) != 0x80u) {
            return 0;
        }
        if (c < 0xC2u) {
            return 0; /* overlong two-byte form */
        }
        return 2;
    }
    if ((c & 0xF0u) == 0xE0u) {
        if (remaining < 3 || (s[1] & 0xC0u) != 0x80u || (s[2] & 0xC0u) != 0x80u) {
            return 0;
        }
        if (c == 0xE0u && s[1] < 0xA0u) {
            return 0; /* overlong three-byte form */
        }
        if (c == 0xEDu && s[1] >= 0xA0u) {
            return 0; /* UTF-16 surrogate half */
        }
        return 3;
    }
    if ((c & 0xF8u) == 0xF0u) {
        if (remaining < 4 || (s[1] & 0xC0u) != 0x80u ||
            (s[2] & 0xC0u) != 0x80u || (s[3] & 0xC0u) != 0x80u) {
            return 0;
        }
        if (c == 0xF0u && s[1] < 0x90u) {
            return 0; /* overlong four-byte form */
        }
        if (c > 0xF4u || (c == 0xF4u && s[1] >= 0x90u)) {
            return 0; /* beyond U+10FFFF */
        }
        return 4;
    }
    return 0; /* continuation byte in leading position, or 0xF8..0xFF */
}

/*
 * Copies `src` into `dst` as valid UTF-8, replacing each invalid byte with
 * U+FFFD.
 *
 * This is the exact inverse of the Windows problem. Win32 hands back UTF-16
 * that converts cleanly; POSIX hands back an arbitrary byte string with no
 * encoding guarantee whatsoever - a filename may be Latin-1, may be a
 * mojibake fragment, may be deliberately malformed. usbs_dir_entry_t.name is
 * *declared* UTF-8 and flows straight into the JSON report writer, so
 * without this a stick carrying one badly-named file produces invalid-UTF-8
 * JSON. On a tool whose input is media supplied by an untrusted party, that
 * is a malformed-output bug reachable by anyone who can hand someone a USB
 * stick.
 *
 * Substituting rather than rejecting is deliberate (ARCHITECTURE.md section
 * 20.4): dropping such entries would let an attacker hide a file from the
 * scan simply by giving it an invalid name, which is strictly worse than
 * reporting it with replacement characters. The invariant is restored here,
 * at the boundary where platform.h declares it, rather than patched further
 * up in report.c.
 *
 * Truncation is bounded and never splits a sequence: a sequence that would
 * not fit whole is dropped rather than half-copied, so the result is always
 * valid UTF-8.
 */
static void sanitize_utf8(const char *src, char *dst, size_t cap)
{
    static const unsigned char k_replacement[3] = { 0xEFu, 0xBFu, 0xBDu };
    const unsigned char *in  = (const unsigned char *)src;
    size_t               len = strlen(src);
    size_t               i   = 0;
    size_t               out = 0;

    if (cap == 0) {
        return;
    }

    while (i < len) {
        size_t seq = utf8_sequence_length(in + i, len - i);

        if (seq == 0) {
            if (out + sizeof(k_replacement) >= cap) {
                break;
            }
            memcpy(dst + out, k_replacement, sizeof(k_replacement));
            out += sizeof(k_replacement);
            i   += 1; /* resynchronise one byte at a time */
            continue;
        }

        if (out + seq >= cap) {
            break;
        }
        memcpy(dst + out, in + i, seq);
        out += seq;
        i   += seq;
    }

    dst[out] = '\0';
}

/* --- directory iteration --- */

struct usbs_dir_iter {
    DIR *dir;
};

usbs_status_t usbs_platform_dir_open(const char *utf8_path, usbs_dir_iter_t **out_iter)
{
    usbs_dir_iter_t *iter;
    DIR             *dir;

    if (utf8_path == NULL || out_iter == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    dir = opendir(utf8_path);
    if (dir == NULL) {
        return usbs_posix_status_from_errno(errno);
    }

    iter = (usbs_dir_iter_t *)calloc(1, sizeof(*iter));
    if (iter == NULL) {
        closedir(dir);
        return USBS_ERR_NO_MEMORY;
    }
    iter->dir = dir;
    *out_iter = iter;
    return USBS_OK;
}

static usbs_bool is_dot_entry(const char *name)
{
    return (strcmp(name, ".") == 0) || (strcmp(name, "..") == 0);
}

/*
 * Fills `out_entry` from one directory entry.
 *
 * fstatat is called with AT_SYMLINK_NOFOLLOW for every entry rather than
 * trusting dirent.d_type, for two independent reasons. d_type is not
 * portable - it reports DT_UNKNOWN on XFS and on several network
 * filesystems, where it carries no information at all - and the scanner needs
 * st_size for its byte accounting regardless, which d_type cannot supply.
 *
 * AT_SYMLINK_NOFOLLOW is the load-bearing part. It is what makes
 * is_reparse_point mean "this entry IS a symlink" rather than "whatever the
 * symlink points at". Using plain stat here would silently invert section
 * 9.3's guarantee that reparse points are never followed into "follow every
 * symlink", which on deliberately hostile media is an unbounded walk (a
 * symlink cycle) or an escape from the scanned volume entirely (a symlink to
 * "/"). It is a safety property, not a portability detail.
 */
static void fill_entry(int dir_fd, const struct dirent *ent,
                       usbs_dir_entry_t *out_entry)
{
    struct stat st;

    memset(out_entry, 0, sizeof(*out_entry));
    sanitize_utf8(ent->d_name, out_entry->name, sizeof(out_entry->name));

    /* A leading dot is POSIX's hidden-file convention. Unlike Windows, where
     * this is a real filesystem attribute, it is only a convention - but it
     * is the one every POSIX tool honours, so it is the honest mapping. */
    out_entry->is_hidden = (ent->d_name[0] == '.');

    if (fstatat(dir_fd, ent->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        /* Unreadable metadata (a permission boundary, or an entry unlinked
         * between readdir and here) must not drop the entry: report what is
         * known and let the caller decide, exactly as the Win32 side does. */
#if defined(DT_DIR) && defined(DT_LNK)
        if (ent->d_type != DT_UNKNOWN) {
            out_entry->is_directory     = (ent->d_type == DT_DIR);
            out_entry->is_reparse_point = (ent->d_type == DT_LNK);
        }
#endif
        return;
    }

    out_entry->is_reparse_point = S_ISLNK(st.st_mode) ? true : false;
    out_entry->is_directory     = S_ISDIR(st.st_mode) ? true : false;
    out_entry->size_bytes =
        out_entry->is_directory ? 0u : (usbs_u64)st.st_size;
}

usbs_status_t usbs_platform_dir_next(usbs_dir_iter_t *iter, usbs_dir_entry_t *out_entry)
{
    if (iter == NULL || out_entry == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    for (;;) {
        const struct dirent *ent;

        /* readdir signals both "end of listing" and "error" with NULL; only
         * errno separates them, so it must be cleared first. */
        errno = 0;
        ent = readdir(iter->dir);
        if (ent == NULL) {
            if (errno != 0) {
                return usbs_posix_status_from_errno(errno);
            }
            return USBS_ERR_NOT_FOUND; /* normal end of iteration */
        }

        if (is_dot_entry(ent->d_name)) {
            continue;
        }

        fill_entry(dirfd(iter->dir), ent, out_entry);
        return USBS_OK;
    }
}

void usbs_platform_dir_close(usbs_dir_iter_t *iter)
{
    if (iter == NULL) {
        return;
    }
    if (iter->dir != NULL) {
        closedir(iter->dir);
    }
    free(iter);
}

/* --- read-only file access --- */

struct usbs_file {
    int fd;
};

usbs_status_t usbs_platform_file_open_read(const char *utf8_path, usbs_file_t **out_file)
{
    usbs_file_t *file;
    int          fd;

    if (utf8_path == NULL || out_file == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    /*
     * Read-only, and deliberately WITHOUT O_NOFOLLOW.
     *
     * O_NOFOLLOW is tempting here, but it would make this call stricter than
     * its Win32 counterpart, which does follow reparse points on open. The
     * never-follow guarantee in section 9.3 belongs to the *traversal* - the
     * scanner skips any entry whose is_reparse_point is set, so a symlink on
     * scanned media never reaches this function. The paths that do reach it
     * directly are the volume's autorun.inf and a user-specified signature
     * list, and refusing to open a signature list because the user symlinked
     * it would be a regression with no safety benefit.
     *
     * O_CLOEXEC because a leaked descriptor across a future exec would be a
     * handle to scanned media this process no longer controls.
     */
    fd = open(utf8_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return usbs_posix_status_from_errno(errno);
    }

    file = (usbs_file_t *)calloc(1, sizeof(*file));
    if (file == NULL) {
        close(fd);
        return USBS_ERR_NO_MEMORY;
    }
    file->fd  = fd;
    *out_file = file;
    return USBS_OK;
}

usbs_status_t usbs_platform_file_read(usbs_file_t *file, void *buf, size_t cap,
                                      size_t *out_read)
{
    ssize_t got;

    if (file == NULL || buf == NULL || out_read == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    *out_read = 0;

    /* Mirrors the Win32 side's clamp: a single read of more than 256 MB is
     * not something this project's bounded buffers ever ask for, and some
     * platforms cap read() below SSIZE_MAX anyway. */
    if (cap > 0x10000000u) {
        cap = 0x10000000u;
    }

    do {
        got = read(file->fd, buf, cap);
    } while (got < 0 && errno == EINTR); /* a signal is not a read failure */

    if (got < 0) {
        return usbs_posix_status_from_errno(errno);
    }
    *out_read = (size_t)got; /* 0 is end of file, not an error */
    return USBS_OK;
}

void usbs_platform_file_close(usbs_file_t *file)
{
    if (file == NULL) {
        return;
    }
    if (file->fd >= 0) {
        close(file->fd);
    }
    free(file);
}

/* --- local data store writes (storage's own files only) --- */

usbs_status_t usbs_platform_make_dirs(const char *utf8_path)
{
    char   partial[FS_POSIX_PATH_MAX];
    size_t len;
    size_t i;

    if (utf8_path == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    len = strlen(utf8_path);
    if (len == 0 || len >= sizeof(partial)) {
        return USBS_ERR_INVALID_ARG;
    }

    /* Create each component in turn; EEXIST is success, matching the Win32
     * side's treatment of ERROR_ALREADY_EXISTS. 0700 rather than 0755: the
     * report store holds a record of what was found on someone's removable
     * media, which is nobody else's business on a shared machine. */
    for (i = 0; i <= len; ++i) {
        if (i == len || utf8_path[i] == '/') {
            if (i == 0) {
                continue; /* leading "/" is the root; nothing to create */
            }
            memcpy(partial, utf8_path, i);
            partial[i] = '\0';

            if (mkdir(partial, 0700) != 0 && errno != EEXIST) {
                return usbs_posix_status_from_errno(errno);
            }
        }
    }
    return USBS_OK;
}

usbs_status_t usbs_platform_write_file(const char *utf8_path, const void *data, size_t len)
{
    const unsigned char *cursor    = (const unsigned char *)data;
    size_t               remaining = len;
    int                  fd;

    if (utf8_path == NULL || (data == NULL && len > 0)) {
        return USBS_ERR_INVALID_ARG;
    }

    /* 0600 for the same reason make_dirs uses 0700. */
    fd = open(utf8_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return usbs_posix_status_from_errno(errno);
    }

    while (remaining > 0) {
        ssize_t written = write(fd, cursor, remaining);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            {
                usbs_status_t status = usbs_posix_status_from_errno(errno);
                close(fd);
                return status;
            }
        }
        if (written == 0) {
            close(fd);
            return USBS_ERR_IO;
        }
        cursor    += (size_t)written;
        remaining -= (size_t)written;
    }

    /* The Win32 side calls FlushFileBuffers here; fsync is the equivalent,
     * and it is what makes the temp-file-then-rename pattern in storage.c
     * actually durable rather than merely ordered. */
    if (fsync(fd) != 0) {
        /* EINVAL means the target cannot be synced (a pipe, some virtual
         * filesystems). The bytes are still written; that is not a failure
         * of this call. */
        if (errno != EINVAL) {
            usbs_status_t status = usbs_posix_status_from_errno(errno);
            close(fd);
            return status;
        }
    }

    if (close(fd) != 0) {
        return usbs_posix_status_from_errno(errno);
    }
    return USBS_OK;
}

usbs_status_t usbs_platform_replace_file(const char *dest, const char *src)
{
    if (dest == NULL || src == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    /* rename(2) is atomic within a filesystem and replaces an existing
     * destination by specification - simpler than the Win32 side, which
     * needs MoveFileExW with explicit REPLACE_EXISTING|WRITE_THROUGH. */
    if (rename(src, dest) != 0) {
        return usbs_posix_status_from_errno(errno);
    }
    return USBS_OK;
}

usbs_status_t usbs_platform_delete_file(const char *utf8_path)
{
    if (utf8_path == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (unlink(utf8_path) != 0) {
        if (errno == ENOENT) {
            return USBS_OK; /* already gone is the requested state */
        }
        return usbs_posix_status_from_errno(errno);
    }
    return USBS_OK;
}
