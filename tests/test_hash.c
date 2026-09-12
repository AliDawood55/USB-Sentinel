/*
 * Verifies the SHA-256 primitive against published NIST test vectors before
 * anything is allowed to trust it. See ARCHITECTURE.md's Phase 4 notes: this
 * is the "verify, don't just trust" step for a security-relevant primitive.
 */
#include <stdio.h>
#include <string.h>

#include "test_util.h"
#include "usbsentinel/platform.h"

static void hash_whole(const char *data, size_t len, char *out_hex)
{
    usbs_hash_ctx_t *ctx = NULL;
    unsigned char    digest[USBS_SHA256_DIGEST_SIZE];

    USBS_CHECK(usbs_ok(usbs_platform_hash_begin(&ctx)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_update(ctx, data, len)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_finish(ctx, digest, out_hex)));
}

static void test_nist_empty_string(void)
{
    char hex[USBS_SHA256_HEX_LEN + 1];
    hash_whole("", 0, hex);
    USBS_CHECK_STR_EQ(hex,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

static void test_nist_abc(void)
{
    char hex[USBS_SHA256_HEX_LEN + 1];
    hash_whole("abc", 3, hex);
    USBS_CHECK_STR_EQ(hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static void test_nist_two_block_message(void)
{
    /* NIST FIPS 180-2 example: the 448-bit message that spans two 512-bit
     * SHA-256 blocks once padded. */
    static const char *msg =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    char hex[USBS_SHA256_HEX_LEN + 1];

    hash_whole(msg, strlen(msg), hex);
    USBS_CHECK_STR_EQ(hex,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

/* Streaming across several update() calls must equal hashing the same bytes
 * in one call - the property every real caller (reading a file in chunks)
 * actually depends on. */
static void test_streaming_matches_single_shot(void)
{
    usbs_hash_ctx_t *ctx = NULL;
    unsigned char    digest[USBS_SHA256_DIGEST_SIZE];
    char             streamed_hex[USBS_SHA256_HEX_LEN + 1];
    char             single_hex[USBS_SHA256_HEX_LEN + 1];

    USBS_CHECK(usbs_ok(usbs_platform_hash_begin(&ctx)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_update(ctx, "a", 1)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_update(ctx, "b", 1)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_update(ctx, "c", 1)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_finish(ctx, digest, streamed_hex)));

    hash_whole("abc", 3, single_hex);
    USBS_CHECK_STR_EQ(streamed_hex, single_hex);
}

/* A zero-length update must be a harmless no-op, not an error. */
static void test_zero_length_update(void)
{
    usbs_hash_ctx_t *ctx = NULL;
    unsigned char    digest[USBS_SHA256_DIGEST_SIZE];
    char             hex[USBS_SHA256_HEX_LEN + 1];

    USBS_CHECK(usbs_ok(usbs_platform_hash_begin(&ctx)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_update(ctx, NULL, 0)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_update(ctx, "abc", 3)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_finish(ctx, digest, hex)));
    USBS_CHECK_STR_EQ(hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static void test_digest_bytes_match_hex(void)
{
    usbs_hash_ctx_t *ctx = NULL;
    unsigned char    digest[USBS_SHA256_DIGEST_SIZE];
    char             hex[USBS_SHA256_HEX_LEN + 1];
    char             rebuilt[USBS_SHA256_HEX_LEN + 1];
    int              i;

    USBS_CHECK(usbs_ok(usbs_platform_hash_begin(&ctx)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_update(ctx, "abc", 3)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_finish(ctx, digest, hex)));

    for (i = 0; i < USBS_SHA256_DIGEST_SIZE; ++i) {
        snprintf(rebuilt + (i * 2), 3, "%02x", digest[i]);
    }
    USBS_CHECK_STR_EQ(rebuilt, hex);
}

static void test_finish_without_hex_buffer(void)
{
    usbs_hash_ctx_t *ctx = NULL;
    unsigned char    digest[USBS_SHA256_DIGEST_SIZE];

    /* out_hex is documented optional. */
    USBS_CHECK(usbs_ok(usbs_platform_hash_begin(&ctx)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_update(ctx, "abc", 3)));
    USBS_CHECK(usbs_ok(usbs_platform_hash_finish(ctx, digest, NULL)));
    USBS_CHECK(digest[0] == 0xba); /* first byte of the known "abc" digest */
}

static void test_invalid_args(void)
{
    usbs_hash_ctx_t *ctx = NULL;
    unsigned char    digest[USBS_SHA256_DIGEST_SIZE];

    USBS_CHECK(usbs_platform_hash_begin(NULL) == USBS_ERR_INVALID_ARG);

    USBS_CHECK(usbs_ok(usbs_platform_hash_begin(&ctx)));
    USBS_CHECK(usbs_platform_hash_update(NULL, "x", 1) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_platform_hash_update(ctx, NULL, 5) == USBS_ERR_INVALID_ARG);
    USBS_CHECK(usbs_platform_hash_finish(NULL, digest, NULL) == USBS_ERR_INVALID_ARG);
    /* usbs_platform_hash_finish(ctx, NULL, ...) frees ctx even on failure
     * (out_digest==NULL is the invalid argument here) - documented behavior,
     * so ctx must not be touched again afterward. */
    USBS_CHECK(usbs_platform_hash_finish(ctx, NULL, NULL) == USBS_ERR_INVALID_ARG);

    /* abort() must be NULL-safe. */
    usbs_platform_hash_abort(NULL);
}

int main(void)
{
    test_nist_empty_string();
    test_nist_abc();
    test_nist_two_block_message();
    test_streaming_matches_single_shot();
    test_zero_length_update();
    test_digest_bytes_match_hex();
    test_finish_without_hex_buffer();
    test_invalid_args();
    return USBS_TEST_RESULT();
}
