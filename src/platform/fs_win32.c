/*
 * Win32 directory traversal, file reads, data-store writes and SHA-256 (via
 * CNG). Alongside device_win32.c and gui/, one of the few translation units
 * permitted to include <windows.h> (ARCHITECTURE.md section 2).
 *
 * Compiled only on Windows: CMake selects this file or its POSIX
 * counterparts fs_posix.c and hash_posix.c (ARCHITECTURE.md section 20.5).
 *
 * Every open here is read-only with FILE_SHARE_READ | FILE_SHARE_WRITE: the
 * read-only policy from ARCHITECTURE.md section 1 is enforced by never
 * requesting write access, not merely by convention.
 */
#include <stdlib.h>
#include <string.h>

#include "usbsentinel/log.h"
#include "usbsentinel/platform.h"


#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <bcrypt.h>

extern usbs_status_t usbs_platform_status_from_win32(unsigned long win32_error);

struct usbs_dir_iter {
    HANDLE          handle;
    WIN32_FIND_DATAW data;
    usbs_bool       have_pending; /* one entry was already fetched by FindFirstFileW */
    usbs_bool       exhausted;
};

struct usbs_file {
    HANDLE handle;
};

static usbs_bool utf8_to_wide(const char *utf8, wchar_t *wide, size_t wide_cap)
{
    int written;
    if (utf8 == NULL || wide == NULL || wide_cap == 0) {
        return false;
    }
    written = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, (int)wide_cap);
    return written > 0;
}

static usbs_bool wide_to_utf8(const wchar_t *wide, char *utf8, size_t utf8_cap)
{
    int written;
    if (wide == NULL || utf8 == NULL || utf8_cap == 0) {
        return false;
    }
    written = WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, (int)utf8_cap, NULL, NULL);
    if (written <= 0) {
        utf8[0] = '\0';
        return false;
    }
    return true;
}

static usbs_bool is_dot_entry(const wchar_t *name)
{
    return (wcscmp(name, L".") == 0) || (wcscmp(name, L"..") == 0);
}

static void fill_entry(const WIN32_FIND_DATAW *data, usbs_dir_entry_t *out_entry)
{
    ULARGE_INTEGER size;

    memset(out_entry, 0, sizeof(*out_entry));
    wide_to_utf8(data->cFileName, out_entry->name, sizeof(out_entry->name));

    out_entry->is_directory =
        (data->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? true : false;
    out_entry->is_reparse_point =
        (data->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ? true : false;
    out_entry->is_hidden =
        (data->dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) ? true : false;

    size.LowPart  = data->nFileSizeLow;
    size.HighPart = (DWORD)data->nFileSizeHigh;
    out_entry->size_bytes = out_entry->is_directory ? 0 : (usbs_u64)size.QuadPart;
}

usbs_status_t usbs_platform_dir_open(const char *utf8_path, usbs_dir_iter_t **out_iter)
{
    wchar_t          wide_path[1024];
    wchar_t          pattern[1040];
    usbs_dir_iter_t *iter;

    if (utf8_path == NULL || out_iter == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (!utf8_to_wide(utf8_path, wide_path, USBS_ARRAY_LEN(wide_path))) {
        return USBS_ERR_INVALID_ARG;
    }

    if (swprintf_s(pattern, USBS_ARRAY_LEN(pattern), L"%ls\\*", wide_path) < 0) {
        return USBS_ERR_INVALID_ARG;
    }

    iter = (usbs_dir_iter_t *)calloc(1, sizeof(*iter));
    if (iter == NULL) {
        return USBS_ERR_NO_MEMORY;
    }

    iter->handle = FindFirstFileW(pattern, &iter->data);
    if (iter->handle == INVALID_HANDLE_VALUE) {
        usbs_status_t status = usbs_platform_status_from_win32(GetLastError());
        free(iter);
        return status;
    }

    iter->have_pending = true;
    iter->exhausted    = false;
    *out_iter = iter;
    return USBS_OK;
}

usbs_status_t usbs_platform_dir_next(usbs_dir_iter_t *iter, usbs_dir_entry_t *out_entry)
{
    if (iter == NULL || out_entry == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    for (;;) {
        if (iter->exhausted) {
            return USBS_ERR_NOT_FOUND;
        }

        if (iter->have_pending) {
            iter->have_pending = false;
        } else {
            if (!FindNextFileW(iter->handle, &iter->data)) {
                iter->exhausted = true;
                /* ERROR_NO_MORE_FILES is normal end-of-listing, not a fault. */
                if (GetLastError() != ERROR_NO_MORE_FILES) {
                    return usbs_platform_status_from_win32(GetLastError());
                }
                return USBS_ERR_NOT_FOUND;
            }
        }

        if (is_dot_entry(iter->data.cFileName)) {
            continue;
        }

        fill_entry(&iter->data, out_entry);
        return USBS_OK;
    }
}

void usbs_platform_dir_close(usbs_dir_iter_t *iter)
{
    if (iter == NULL) {
        return;
    }
    if (iter->handle != INVALID_HANDLE_VALUE && iter->handle != NULL) {
        FindClose(iter->handle);
    }
    free(iter);
}

usbs_status_t usbs_platform_file_open_read(const char *utf8_path, usbs_file_t **out_file)
{
    wchar_t     wide_path[1024];
    usbs_file_t *file;
    HANDLE      handle;

    if (utf8_path == NULL || out_file == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (!utf8_to_wide(utf8_path, wide_path, USBS_ARRAY_LEN(wide_path))) {
        return USBS_ERR_INVALID_ARG;
    }

    handle = CreateFileW(wide_path,
                         GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_FLAG_SEQUENTIAL_SCAN,
                         NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        return usbs_platform_status_from_win32(GetLastError());
    }

    file = (usbs_file_t *)calloc(1, sizeof(*file));
    if (file == NULL) {
        CloseHandle(handle);
        return USBS_ERR_NO_MEMORY;
    }
    file->handle = handle;
    *out_file = file;
    return USBS_OK;
}

usbs_status_t usbs_platform_file_read(usbs_file_t *file, void *buf, size_t cap,
                                      size_t *out_read)
{
    DWORD read = 0;

    if (file == NULL || buf == NULL || out_read == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    /* Clamp: ReadFile takes a DWORD; callers are expected to pass reasonably
     * sized buffers, but never let a huge cap silently truncate/overflow. */
    if (cap > 0x10000000u) {
        cap = 0x10000000u;
    }

    if (!ReadFile(file->handle, buf, (DWORD)cap, &read, NULL)) {
        return usbs_platform_status_from_win32(GetLastError());
    }
    *out_read = (size_t)read;
    return USBS_OK;
}

void usbs_platform_file_close(usbs_file_t *file)
{
    if (file == NULL) {
        return;
    }
    if (file->handle != INVALID_HANDLE_VALUE && file->handle != NULL) {
        CloseHandle(file->handle);
    }
    free(file);
}

/* --- local data store writes (storage's own files only) --- */

usbs_status_t usbs_platform_make_dirs(const char *utf8_path)
{
    wchar_t wide[1024];
    wchar_t partial[1024];
    size_t  len;
    size_t  i;

    if (utf8_path == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (!utf8_to_wide(utf8_path, wide, USBS_ARRAY_LEN(wide))) {
        return USBS_ERR_INVALID_ARG;
    }

    len = wcslen(wide);
    if (len == 0 || len >= USBS_ARRAY_LEN(partial)) {
        return USBS_ERR_INVALID_ARG;
    }

    /* Create each path component in turn; ERROR_ALREADY_EXISTS is success. */
    for (i = 0; i <= len; ++i) {
        if (i == len || wide[i] == L'\\' || wide[i] == L'/') {
            if (i == 0) {
                continue; /* leading slash: nothing to create yet */
            }
            /* Skip the bare drive root ("C:") - CreateDirectory rejects it. */
            if (i == 2 && wide[1] == L':') {
                continue;
            }
            memcpy(partial, wide, i * sizeof(wchar_t));
            partial[i] = L'\0';

            if (!CreateDirectoryW(partial, NULL)) {
                DWORD err = GetLastError();
                if (err != ERROR_ALREADY_EXISTS) {
                    return usbs_platform_status_from_win32(err);
                }
            }
        }
    }
    return USBS_OK;
}

usbs_status_t usbs_platform_write_file(const char *utf8_path, const void *data, size_t len)
{
    wchar_t wide_path[1024];
    HANDLE  handle;
    const unsigned char *cursor = (const unsigned char *)data;
    size_t  remaining = len;

    if (utf8_path == NULL || (data == NULL && len > 0)) {
        return USBS_ERR_INVALID_ARG;
    }
    if (!utf8_to_wide(utf8_path, wide_path, USBS_ARRAY_LEN(wide_path))) {
        return USBS_ERR_INVALID_ARG;
    }

    handle = CreateFileW(wide_path,
                         GENERIC_WRITE,
                         FILE_SHARE_READ,
                         NULL,
                         CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL,
                         NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        return usbs_platform_status_from_win32(GetLastError());
    }

    while (remaining > 0) {
        DWORD chunk = (remaining > 0x10000000u) ? 0x10000000u : (DWORD)remaining;
        DWORD written = 0;

        if (!WriteFile(handle, cursor, chunk, &written, NULL) || written == 0) {
            usbs_status_t status = usbs_platform_status_from_win32(GetLastError());
            CloseHandle(handle);
            return status;
        }
        cursor    += written;
        remaining -= written;
    }

    if (!FlushFileBuffers(handle)) {
        usbs_status_t status = usbs_platform_status_from_win32(GetLastError());
        CloseHandle(handle);
        return status;
    }

    CloseHandle(handle);
    return USBS_OK;
}

usbs_status_t usbs_platform_replace_file(const char *dest, const char *src)
{
    wchar_t wide_dest[1024];
    wchar_t wide_src[1024];

    if (dest == NULL || src == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (!utf8_to_wide(dest, wide_dest, USBS_ARRAY_LEN(wide_dest)) ||
        !utf8_to_wide(src, wide_src, USBS_ARRAY_LEN(wide_src))) {
        return USBS_ERR_INVALID_ARG;
    }

    if (!MoveFileExW(wide_src, wide_dest,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        return usbs_platform_status_from_win32(GetLastError());
    }
    return USBS_OK;
}

usbs_status_t usbs_platform_delete_file(const char *utf8_path)
{
    wchar_t wide_path[1024];

    if (utf8_path == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (!utf8_to_wide(utf8_path, wide_path, USBS_ARRAY_LEN(wide_path))) {
        return USBS_ERR_INVALID_ARG;
    }

    if (!DeleteFileW(wide_path)) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            return USBS_OK;
        }
        return usbs_platform_status_from_win32(err);
    }
    return USBS_OK;
}

/* --- SHA-256 via Windows CNG (bcrypt.dll) --- */

struct usbs_hash_ctx {
    BCRYPT_HASH_HANDLE handle;
    PBYTE              object;
};

/* The algorithm provider is opened once, lazily, and kept for the process
 * lifetime - opening it per hash would renegotiate a provider on every file.
 * Single-threaded (ARCHITECTURE.md section 9.3), so no lock is needed. */
static BCRYPT_ALG_HANDLE g_sha256_alg = NULL;

static usbs_status_t ensure_sha256_alg(void)
{
    NTSTATUS status;

    if (g_sha256_alg != NULL) {
        return USBS_OK;
    }
    status = BCryptOpenAlgorithmProvider(&g_sha256_alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        g_sha256_alg = NULL;
        return USBS_ERR_INTERNAL;
    }
    return USBS_OK;
}

usbs_status_t usbs_platform_hash_begin(usbs_hash_ctx_t **out_ctx)
{
    usbs_hash_ctx_t *ctx;
    DWORD            object_len = 0;
    DWORD            copied     = 0;
    NTSTATUS         status;

    if (out_ctx == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (!usbs_ok(ensure_sha256_alg())) {
        return USBS_ERR_INTERNAL;
    }

    status = BCryptGetProperty(g_sha256_alg, BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&object_len, sizeof(object_len), &copied, 0);
    if (!BCRYPT_SUCCESS(status) || object_len == 0) {
        return USBS_ERR_INTERNAL;
    }

    ctx = (usbs_hash_ctx_t *)calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return USBS_ERR_NO_MEMORY;
    }
    ctx->object = (PBYTE)malloc(object_len);
    if (ctx->object == NULL) {
        free(ctx);
        return USBS_ERR_NO_MEMORY;
    }

    status = BCryptCreateHash(g_sha256_alg, &ctx->handle, ctx->object, object_len,
                              NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        free(ctx->object);
        free(ctx);
        return USBS_ERR_INTERNAL;
    }

    *out_ctx = ctx;
    return USBS_OK;
}

usbs_status_t usbs_platform_hash_update(usbs_hash_ctx_t *ctx, const void *data, size_t len)
{
    NTSTATUS status;

    if (ctx == NULL || (data == NULL && len > 0)) {
        return USBS_ERR_INVALID_ARG;
    }
    if (len == 0) {
        return USBS_OK;
    }
    if (len > 0xFFFFFFFFul) {
        /* BCryptHashData takes a ULONG length; callers are expected to feed
         * bounded chunks (matching every existing read-loop pattern), so
         * this is a defensive cap, not an expected path. */
        return USBS_ERR_INVALID_ARG;
    }

    status = BCryptHashData(ctx->handle, (PUCHAR)data, (ULONG)len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return USBS_ERR_INTERNAL;
    }
    return USBS_OK;
}

usbs_status_t usbs_platform_hash_finish(usbs_hash_ctx_t *ctx,
                                        unsigned char     out_digest[USBS_SHA256_DIGEST_SIZE],
                                        char             *out_hex)
{
    NTSTATUS status;
    int      i;

    if (ctx == NULL || out_digest == NULL) {
        usbs_platform_hash_abort(ctx);
        return USBS_ERR_INVALID_ARG;
    }

    status = BCryptFinishHash(ctx->handle, out_digest, USBS_SHA256_DIGEST_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        usbs_platform_hash_abort(ctx);
        return USBS_ERR_INTERNAL;
    }

    if (out_hex != NULL) {
        for (i = 0; i < USBS_SHA256_DIGEST_SIZE; ++i) {
            snprintf(out_hex + (i * 2), 3, "%02x", out_digest[i]);
        }
    }

    BCryptDestroyHash(ctx->handle);
    free(ctx->object);
    free(ctx);
    return USBS_OK;
}

void usbs_platform_hash_abort(usbs_hash_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->handle != NULL) {
        BCryptDestroyHash(ctx->handle);
    }
    free(ctx->object);
    free(ctx);
}

