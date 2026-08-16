#include "crypto/ripemd160.h"
#include <cstring>

// RIPEMD-160 — implementasi standar (dipublikasikan oleh Dobbertin/Bosselaers/Preneel).
// Menggunakan konstanta dan rotasi dari spesifikasi resmi RIPEMD-160.

namespace cdx {

namespace {

struct RIPEMD160_CTX {
    uint32_t h[5];
    uint64_t total;   // total bytes
    uint8_t buf[64];
    size_t buflen;
};

inline uint32_t rol(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

inline uint32_t f1(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
inline uint32_t f2(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
inline uint32_t f3(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
inline uint32_t f4(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
inline uint32_t f5(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }

const uint32_t R_ADD[5] = {0x00000000u, 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xA953FD4Eu};
const uint32_t L_ADD[5] = {0x50A28BE6u, 0x5C4DD124u, 0x6D703EF3u, 0x7A6D76E9u, 0x00000000u};

const int R_R[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
};

const int L_R[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};

const int R_S[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};

const int L_S[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

inline uint32_t f1of(int round, uint32_t x, uint32_t y, uint32_t z) {
    switch (round) {
        case 0: return f1(x, y, z);
        case 1: return f2(x, y, z);
        case 2: return f3(x, y, z);
        case 3: return f4(x, y, z);
        default: return f5(x, y, z);
    }
}

inline uint32_t f5of(int round, uint32_t x, uint32_t y, uint32_t z) {
    switch (round) {
        case 0: return f5(x, y, z);
        case 1: return f4(x, y, z);
        case 2: return f3(x, y, z);
        case 3: return f2(x, y, z);
        default: return f1(x, y, z);
    }
}

void rmd160_transform(uint32_t* state, const uint8_t* block) {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) {
        x[i] = (uint32_t)block[i * 4] |
               ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }
    uint32_t al = state[0], bl = state[1], cl = state[2], dl = state[3], el = state[4];
    uint32_t ar = state[0], br = state[1], cr = state[2], dr = state[3], er = state[4];

    for (int j = 0; j < 80; ++j) {
        // left line: f(j), K(j)
        int round = j / 16;
        uint32_t t = rol(al + f1of(round, bl, cl, dl) + x[R_R[j]] + R_ADD[round], R_S[j]) + el;
        al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t;
        // right line: f'(round) terbalik (round 0 -> f5), K'[round] berurutan
        int rround = 4 - round;
        uint32_t tr = rol(ar + f1of(rround, br, cr, dr) + x[L_R[j]] + L_ADD[round], L_S[j]) + er;
        ar = er; er = dr; dr = rol(cr, 10); cr = br; br = tr;
    }
    uint32_t t = state[1] + cl + dr;
    state[1] = state[2] + dl + er;
    state[2] = state[3] + el + ar;
    state[3] = state[4] + al + br;
    state[4] = state[0] + bl + cr;
    state[0] = t;
}

void rmd160_init(RIPEMD160_CTX* ctx) {
    ctx->h[0] = 0x67452301u;
    ctx->h[1] = 0xEFCDAB89u;
    ctx->h[2] = 0x98BADCFEu;
    ctx->h[3] = 0x10325476u;
    ctx->h[4] = 0xC3D2E1F0u;
    ctx->total = 0;
    ctx->buflen = 0;
}

void rmd160_update(RIPEMD160_CTX* ctx, const uint8_t* data, size_t len) {
    ctx->total += len;
    while (len > 0) {
        size_t take = 64 - ctx->buflen;
        if (take > len) take = len;
        std::memcpy(ctx->buf + ctx->buflen, data, take);
        ctx->buflen += take;
        data += take;
        len -= take;
        if (ctx->buflen == 64) {
            rmd160_transform(ctx->h, ctx->buf);
            ctx->buflen = 0;
        }
    }
}

void rmd160_final(RIPEMD160_CTX* ctx, uint8_t out[20]) {
    uint64_t bitlen = ctx->total * 8;
    uint8_t pad[72];
    size_t padlen = ctx->buflen < 56 ? 56 - ctx->buflen : 120 - ctx->buflen;
    std::memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    rmd160_update(ctx, pad, padlen);
    uint8_t lenbytes[8];
    for (int i = 0; i < 8; ++i)
        lenbytes[i] = (uint8_t)(bitlen >> (8 * i));
    rmd160_update(ctx, lenbytes, 8);
    for (int i = 0; i < 5; ++i) {
        out[i * 4] = (uint8_t)(ctx->h[i]);
        out[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(ctx->h[i] >> 24);
    }
}

} // namespace

void ripemd160(const uint8_t* data, size_t len, uint8_t out[20]) {
    RIPEMD160_CTX ctx;
    rmd160_init(&ctx);
    rmd160_update(&ctx, data, len);
    rmd160_final(&ctx, out);
}

} // namespace cdx
