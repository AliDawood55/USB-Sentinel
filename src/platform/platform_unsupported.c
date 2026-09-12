/*
 * Fallback platform backend for a host that is neither Windows nor POSIX.
 *
 * Before Phase 14 this role was played by the `#else` half of fs_win32.c and
 * device_win32.c, because CMake compiled those files unconditionally. Now
 * that CMake selects one backend per host, those branches are gone and this
 * file keeps the property they provided: the project still configures,
 * compiles and links somewhere unexpected, reporting USBS_ERR_UNSUPPORTED
 * for anything platform-specific instead of failing at link time with
 * undefined symbols.
 *
 * Nothing here should ever be reached in practice. It exists so that adding
 * a fourth platform is a matter of writing its backend, not of first
 * untangling why the build breaks without one.
 */
#include <string.h>

#include "usbsentinel/platform.h"

/* --- device enumeration and capabilities --- */

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

/* --- cancellation --- */

usbs_status_t usbs_platform_install_cancel_handler(void)
{
    return USBS_ERR_UNSUPPORTED;
}

usbs_bool usbs_platform_cancel_requested(void)
{
    return false;
}

/* --- directory traversal and file access --- */

usbs_status_t usbs_platform_dir_open(const char *utf8_path, usbs_dir_iter_t **out_iter)
{
    USBS_UNUSED(utf8_path);
    USBS_UNUSED(out_iter);
    return USBS_ERR_UNSUPPORTED;
}

usbs_status_t usbs_platform_dir_next(usbs_dir_iter_t *iter, usbs_dir_entry_t *out_entry)
{
    USBS_UNUSED(iter);
    USBS_UNUSED(out_entry);
    return USBS_ERR_UNSUPPORTED;
}

void usbs_platform_dir_close(usbs_dir_iter_t *iter)
{
    USBS_UNUSED(iter);
}

usbs_status_t usbs_platform_file_open_read(const char *utf8_path, usbs_file_t **out_file)
{
    USBS_UNUSED(utf8_path);
    USBS_UNUSED(out_file);
    return USBS_ERR_UNSUPPORTED;
}

usbs_status_t usbs_platform_file_read(usbs_file_t *file, void *buf, size_t cap,
                                      size_t *out_read)
{
    USBS_UNUSED(file);
    USBS_UNUSED(buf);
    USBS_UNUSED(cap);
    USBS_UNUSED(out_read);
    return USBS_ERR_UNSUPPORTED;
}

void usbs_platform_file_close(usbs_file_t *file)
{
    USBS_UNUSED(file);
}

/* --- local data store writes --- */

usbs_status_t usbs_platform_make_dirs(const char *utf8_path)
{
    USBS_UNUSED(utf8_path);
    return USBS_ERR_UNSUPPORTED;
}

usbs_status_t usbs_platform_write_file(const char *utf8_path, const void *data, size_t len)
{
    USBS_UNUSED(utf8_path);
    USBS_UNUSED(data);
    USBS_UNUSED(len);
    return USBS_ERR_UNSUPPORTED;
}

usbs_status_t usbs_platform_replace_file(const char *dest, const char *src)
{
    USBS_UNUSED(dest);
    USBS_UNUSED(src);
    return USBS_ERR_UNSUPPORTED;
}

usbs_status_t usbs_platform_delete_file(const char *utf8_path)
{
    USBS_UNUSED(utf8_path);
    return USBS_ERR_UNSUPPORTED;
}

/* --- SHA-256 --- */

usbs_status_t usbs_platform_hash_begin(usbs_hash_ctx_t **out_ctx)
{
    USBS_UNUSED(out_ctx);
    return USBS_ERR_UNSUPPORTED;
}

usbs_status_t usbs_platform_hash_update(usbs_hash_ctx_t *ctx, const void *data, size_t len)
{
    USBS_UNUSED(ctx);
    USBS_UNUSED(data);
    USBS_UNUSED(len);
    return USBS_ERR_UNSUPPORTED;
}

usbs_status_t usbs_platform_hash_finish(usbs_hash_ctx_t *ctx,
                                        unsigned char     out_digest[USBS_SHA256_DIGEST_SIZE],
                                        char             *out_hex)
{
    USBS_UNUSED(ctx);
    USBS_UNUSED(out_digest);
    USBS_UNUSED(out_hex);
    return USBS_ERR_UNSUPPORTED;
}

void usbs_platform_hash_abort(usbs_hash_ctx_t *ctx)
{
    USBS_UNUSED(ctx);
}
