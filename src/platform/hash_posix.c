/*
 * SHA-256 for POSIX hosts, behind the streaming contract in platform.h.
 *
 * Two backends, chosen by host rather than by preference
 * (ARCHITECTURE.md section 20.6):
 *
 *   macOS  - CommonCrypto (<CommonCrypto/CommonDigest.h>). First-party, in
 *            libSystem, needs no link flag and no package, and exposes
 *            exactly the Init/Update/Final shape this API already has. It is
 *            the direct analogue of preferring CNG on Windows over bringing
 *            in a crypto library.
 *
 *   others - the vendored primitive in sha256.c. Linux has no first-party
 *            equivalent, so the real choice is OpenSSL or ~180 lines with
 *            published test vectors; see sha256.h for why this project takes
 *            the second. Packagers who would rather link the system crypto
 *            library can configure with -DUSBS_USE_OPENSSL=ON.
 *
 * Whichever backend is active, tests/test_hash.c asserts the same NIST
 * vectors against it, so "the hash is correct here" is checked per platform
 * rather than assumed from the Windows result.
 */
#include <stdlib.h>
#include <string.h>

#include "usbsentinel/platform.h"

#if defined(USBS_USE_OPENSSL)
#include <openssl/sha.h>
typedef SHA256_CTX usbs_hash_backend_t;
#elif defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
typedef CC_SHA256_CTX usbs_hash_backend_t;
#else
#include "sha256.h"
typedef usbs_sha256_t usbs_hash_backend_t;
#endif

struct usbs_hash_ctx {
    usbs_hash_backend_t backend;
};

static void backend_init(usbs_hash_backend_t *backend)
{
#if defined(USBS_USE_OPENSSL)
    SHA256_Init(backend);
#elif defined(__APPLE__)
    CC_SHA256_Init(backend);
#else
    usbs_sha256_init(backend);
#endif
}

static void backend_update(usbs_hash_backend_t *backend, const void *data, size_t len)
{
#if defined(USBS_USE_OPENSSL)
    SHA256_Update(backend, data, len);
#elif defined(__APPLE__)
    /* CC_SHA256_Update takes a CC_LONG (32-bit), so a single call cannot be
     * handed more than 4 GB. usbs_platform_file_read already clamps reads
     * far below that, but the loop makes the bound a property of this
     * function rather than an assumption about its callers. */
    {
        const unsigned char *cursor = (const unsigned char *)data;
        while (len > 0) {
            CC_LONG chunk = (len > 0x10000000u) ? 0x10000000u : (CC_LONG)len;
            CC_SHA256_Update(backend, cursor, chunk);
            cursor += chunk;
            len    -= chunk;
        }
    }
#else
    usbs_sha256_update(backend, data, len);
#endif
}

static void backend_final(usbs_hash_backend_t *backend,
                          unsigned char out_digest[USBS_SHA256_DIGEST_SIZE])
{
#if defined(USBS_USE_OPENSSL)
    SHA256_Final(out_digest, backend);
#elif defined(__APPLE__)
    CC_SHA256_Final(out_digest, backend);
#else
    usbs_sha256_final(backend, out_digest);
#endif
}

usbs_status_t usbs_platform_hash_begin(usbs_hash_ctx_t **out_ctx)
{
    usbs_hash_ctx_t *ctx;

    if (out_ctx == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    ctx = (usbs_hash_ctx_t *)calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return USBS_ERR_NO_MEMORY;
    }
    backend_init(&ctx->backend);
    *out_ctx = ctx;
    return USBS_OK;
}

usbs_status_t usbs_platform_hash_update(usbs_hash_ctx_t *ctx, const void *data, size_t len)
{
    if (ctx == NULL || (data == NULL && len > 0)) {
        return USBS_ERR_INVALID_ARG;
    }
    if (len == 0) {
        return USBS_OK; /* documented no-op */
    }
    backend_update(&ctx->backend, data, len);
    return USBS_OK;
}

usbs_status_t usbs_platform_hash_finish(usbs_hash_ctx_t *ctx,
                                        unsigned char     out_digest[USBS_SHA256_DIGEST_SIZE],
                                        char             *out_hex)
{
    unsigned char digest[USBS_SHA256_DIGEST_SIZE];
    size_t        i;

    if (ctx == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (out_digest == NULL) {
        /* Frees ctx even on the error path, as platform.h promises: the
         * caller must never call hash_abort() after hash_finish(). */
        free(ctx);
        return USBS_ERR_INVALID_ARG;
    }

    backend_final(&ctx->backend, digest);
    memcpy(out_digest, digest, sizeof(digest));

    if (out_hex != NULL) {
        static const char k_hex[] = "0123456789abcdef";
        for (i = 0; i < sizeof(digest); ++i) {
            out_hex[i * 2u]      = k_hex[(digest[i] >> 4) & 0x0Fu];
            out_hex[i * 2u + 1u] = k_hex[digest[i] & 0x0Fu];
        }
        out_hex[USBS_SHA256_HEX_LEN] = '\0';
    }

    free(ctx);
    return USBS_OK;
}

void usbs_platform_hash_abort(usbs_hash_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    /* The backend state holds a tail of file content. */
    memset(&ctx->backend, 0, sizeof(ctx->backend));
    free(ctx);
}
