/*
 * SHA-256 (FIPS 180-4), for POSIX hosts that have no first-party provider.
 *
 * Windows uses CNG and macOS uses CommonCrypto - both first-party, both
 * preferred where they exist (ARCHITECTURE.md section 20.6). Linux has no
 * equivalent, so the choice there is a third-party dependency or a vendored
 * primitive, and this project's stance throughout has been to avoid the
 * dependency where the alternative is small and fully verifiable.
 *
 * This is not a general-purpose crypto implementation and must not be used
 * as one. It backs known-file matching: the inputs are file contents, there
 * are no keys and no secrets, and nothing here is required to be
 * constant-time. What makes vendoring defensible is that SHA-256 is a
 * deterministic function with published NIST test vectors, which
 * tests/test_hash.c already asserts against - correctness here is checkable
 * rather than a matter of trust.
 */
#ifndef USBSENTINEL_SHA256_H
#define USBSENTINEL_SHA256_H

#include <stddef.h>

#include "usbsentinel/types.h"

typedef struct usbs_sha256 {
    usbs_u32      state[8];
    usbs_u64      bit_count;
    unsigned char buffer[64];
    size_t        buffered;
} usbs_sha256_t;

void usbs_sha256_init(usbs_sha256_t *ctx);
void usbs_sha256_update(usbs_sha256_t *ctx, const void *data, size_t len);
void usbs_sha256_final(usbs_sha256_t *ctx, unsigned char out_digest[32]);

#endif /* USBSENTINEL_SHA256_H */
