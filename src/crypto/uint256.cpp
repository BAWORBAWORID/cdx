#include "crypto/uint256.h"
#include <cstdio>

namespace cdx {

uint32_t uint256::getCompact() const {
    // Algoritma arith_uint256::GetCompact (bitcoin).
    unsigned int nSize = (unsigned int)((getBitLength() + 7) / 8);
    uint32_t nCompact = 0;
    if (nSize == 0) return 0;
    if (nSize <= 3) {
        nCompact = (uint32_t)w[0] << (8 * (3 - nSize));
    } else {
        // geser kanan agar muat 3 byte mantissa
        uint256 bn = *this >> (8 * (nSize - 3));
        nCompact = (uint32_t)bn.w[0];
    }
    // bit 0x00800000 menandakan tanda: jika mantissa memakainya, geser & naikkan size
    if (nCompact & 0x00800000u) {
        nCompact >>= 8;
        ++nSize;
    }
    nCompact |= nSize << 24;
    return nCompact;
}

uint256 uint256::setCompact(uint32_t nCompact) {
    uint256 result;
    int nSize = nCompact >> 24;
    uint32_t nWord = nCompact & 0x007fffff;
    if (nSize <= 3) {
        nWord >>= 8 * (3 - nSize);
        result.w[0] = nWord;
    } else {
        result.w[0] = nWord;
        result <<= 8 * (nSize - 3);
    }
    return result;
}

uint256 uint256::fromHex(const std::string& hex) {
    uint256 r;
    std::string h = hex;
    if (h.size() > 64) h = h.substr(h.size() - 64);
    while (h.size() < 64) h = "0" + h;
    auto nib = [](char c) -> uint64_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    // hex display order: h[0] = byte paling signifikan (MSB-first)
    for (int k = 0; k < 32; ++k) {
        uint64_t byte = (nib(h[k * 2]) << 4) | nib(h[k * 2 + 1]);
        // byte ke-k dari MSB = byte ke-(31-k) dari LSB
        int wordIdx = (31 - k) / 8;
        int shift = (31 - k) % 8;
        r.w[wordIdx] |= byte << (8 * shift);
    }
    return r;
}

uint256 uint256::fromHexReversed(const std::string& hex) {
    // hash display (big-endian display): byte terakhir di hex = byte pertama (LSB)
    uint256 r;
    std::string h = hex;
    if (h.size() > 64) h = h.substr(h.size() - 64);
    while (h.size() < 64) h = "0" + h;
    uint8_t bytes[32];
    auto nib = [&](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    for (int i = 0; i < 32; ++i)
        bytes[i] = (uint8_t)(nib(h[i * 2]) << 4 | nib(h[i * 2 + 1]));
    // display order: bytes[0] = MSB; LSB di bytes[31]
    r.setBytesLE(bytes); // little-endian mengambil bytes[0] sebagai LSB => balik
    // balik
    for (int i = 0; i < 16; ++i) {
        uint8_t t = bytes[i];
        bytes[i] = bytes[31 - i];
        bytes[31 - i] = t;
    }
    r.setBytesLE(bytes);
    return r;
}

} // namespace cdx
