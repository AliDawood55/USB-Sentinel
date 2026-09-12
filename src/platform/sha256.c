/*
 * SHA-256 (FIPS 180-4). See sha256.h for why this is vendored rather than
 * taken as a dependency, and for the limits on what it may be used for.
 *
 * A direct transcription of the specification: the round constants are the
 * first 32 bits of the fractional parts of the cube roots of the first 64
 * primes, and the initial state the same of the square roots of the first
 * eight. Written for legibility against the spec rather than for speed -
 * hashing here is bounded by file I/O, not by the compression function, and
 * an unrolled or SIMD variant would trade the one property that makes
 * vendoring defensible (you can read it next to FIPS 180-4 and check it) for
 * throughput this project never needed.
 */
#include <string.h>

#include "sha256.h"

static const usbs_u32 k_round_constants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

/* Rotation is written as a function so the 32-bit mask is applied in exactly
 * one place; a macro here is the classic spot for an unmasked shift on a
 * platform where unsigned int is wider than 32 bits. */
static usbs_u32 rotr32(usbs_u32 value, unsigned bits)
{
    return (usbs_u32)((value >> bits) | (value << (32u - bits)));
}

static void sha256_compress(usbs_u32 state[8], const unsigned char block[64])
{
    usbs_u32 w[64];
    usbs_u32 a, b, c, d, e, f, g, h;
    unsigned i;

    /* Big-endian load, done byte by byte rather than by casting the block to
     * a usbs_u32 pointer: that would be both an alignment violation and
     * wrong on a little-endian host. */
    for (i = 0; i < 16u; ++i) {
        w[i] = ((usbs_u32)block[i * 4u] << 24) |
               ((usbs_u32)block[i * 4u + 1u] << 16) |
               ((usbs_u32)block[i * 4u + 2u] << 8) |
               ((usbs_u32)block[i * 4u + 3u]);
    }
    for (i = 16u; i < 64u; ++i) {
        usbs_u32 s0 = rotr32(w[i - 15u], 7) ^ rotr32(w[i - 15u], 18) ^ (w[i - 15u] >> 3);
        usbs_u32 s1 = rotr32(w[i - 2u], 17) ^ rotr32(w[i - 2u], 19) ^ (w[i - 2u] >> 10);
        w[i] = (usbs_u32)(w[i - 16u] + s0 + w[i - 7u] + s1);
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64u; ++i) {
        usbs_u32 s1    = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        usbs_u32 ch    = (usbs_u32)((e & f) ^ ((~e) & g));
        usbs_u32 temp1 = (usbs_u32)(h + s1 + ch + k_round_constants[i] + w[i]);
        usbs_u32 s0    = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        usbs_u32 maj   = (usbs_u32)((a & b) ^ (a & c) ^ (b & c));
        usbs_u32 temp2 = (usbs_u32)(s0 + maj);

        h = g;
        g = f;
        f = e;
        e = (usbs_u32)(d + temp1);
        d = c;
        c = b;
        b = a;
        a = (usbs_u32)(temp1 + temp2);
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void usbs_sha256_init(usbs_sha256_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->bit_count = 0;
    ctx->buffered  = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void usbs_sha256_update(usbs_sha256_t *ctx, const void *data, size_t len)
{
    const unsigned char *cursor = (const unsigned char *)data;

    if (ctx == NULL || (data == NULL && len > 0)) {
        return;
    }

    ctx->bit_count += (usbs_u64)len * 8u;

    /* Top up a partial block first, then run whole blocks straight from the
     * caller's buffer, then keep the remainder. This is what makes the
     * streaming contract in platform.h hold for any chunking the caller
     * chooses. */
    if (ctx->buffered > 0) {
        size_t need = sizeof(ctx->buffer) - ctx->buffered;
        size_t take = (len < need) ? len : need;

        memcpy(ctx->buffer + ctx->buffered, cursor, take);
        ctx->buffered += take;
        cursor        += take;
        len           -= take;

        if (ctx->buffered == sizeof(ctx->buffer)) {
            sha256_compress(ctx->state, ctx->buffer);
            ctx->buffered = 0;
        }
    }

    while (len >= sizeof(ctx->buffer)) {
        sha256_compress(ctx->state, cursor);
        cursor += sizeof(ctx->buffer);
        len    -= sizeof(ctx->buffer);
    }

    if (len > 0) {
        memcpy(ctx->buffer, cursor, len);
        ctx->buffered = len;
    }
}

void usbs_sha256_final(usbs_sha256_t *ctx, unsigned char out_digest[32])
{
    usbs_u64 bit_count;
    unsigned i;

    if (ctx == NULL || out_digest == NULL) {
        return;
    }
    bit_count = ctx->bit_count;

    /* Padding: a single 0x80 byte, then zeroes, then the length as a 64-bit
     * big-endian bit count in the final eight bytes. If the length would not
     * fit in the current block, pad this one out and emit one more. */
    ctx->buffer[ctx->buffered++] = 0x80u;
    if (ctx->buffered > 56u) {
        memset(ctx->buffer + ctx->buffered, 0, sizeof(ctx->buffer) - ctx->buffered);
        sha256_compress(ctx->state, ctx->buffer);
        ctx->buffered = 0;
    }
    memset(ctx->buffer + ctx->buffered, 0, 56u - ctx->buffered);

    for (i = 0; i < 8u; ++i) {
        ctx->buffer[56u + i] = (unsigned char)((bit_count >> (56u - 8u * i)) & 0xFFu);
    }
    sha256_compress(ctx->state, ctx->buffer);

    for (i = 0; i < 8u; ++i) {
        out_digest[i * 4u]      = (unsigned char)((ctx->state[i] >> 24) & 0xFFu);
        out_digest[i * 4u + 1u] = (unsigned char)((ctx->state[i] >> 16) & 0xFFu);
        out_digest[i * 4u + 2u] = (unsigned char)((ctx->state[i] >> 8) & 0xFFu);
        out_digest[i * 4u + 3u] = (unsigned char)(ctx->state[i] & 0xFFu);
    }

    /* The context holds a tail of file content; do not leave it on the stack
     * or heap for the next caller to inherit. */
    memset(ctx, 0, sizeof(*ctx));
}
