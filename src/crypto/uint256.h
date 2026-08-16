#pragma once
#include <cstdint>
#include <cstring>
#include <string>

namespace cdx {

// ---------------------------------------------------------------------------
// uint256 — integer 256-bit unsigned, little-endian word order (bitcoin-style).
// Digunakan untuk: hash block, target difficulty, chain work.
// ---------------------------------------------------------------------------
class uint256 {
public:
    // 4 kata 64-bit; index 0 = least significant.
    uint64_t w[4];

    uint256() { clear(); }

    explicit uint256(uint64_t v) { clear(); w[0] = v; }

    void clear() { std::memset(w, 0, sizeof(w)); }

    bool isZero() const { return (w[0] | w[1] | w[2] | w[3]) == 0; }
    bool isMax() const {
        return w[0] == ~0ull && w[1] == ~0ull && w[2] == ~0ull && w[3] == ~0ull;
    }

    explicit operator bool() const { return !isZero(); }
    bool operator!() const { return isZero(); }

    // --- perbandingan (big-endian semantics) ---
    bool operator==(const uint256& o) const {
        return w[0] == o.w[0] && w[1] == o.w[1] && w[2] == o.w[2] && w[3] == o.w[3];
    }
    bool operator!=(const uint256& o) const { return !(*this == o); }
    bool operator<(const uint256& o) const {
        for (int i = 3; i >= 0; --i) {
            if (w[i] != o.w[i]) return w[i] < o.w[i];
        }
        return false;
    }
    bool operator>(const uint256& o) const { return o < *this; }
    bool operator<=(const uint256& o) const { return !(o < *this); }
    bool operator>=(const uint256& o) const { return !(*this < o); }

    // --- bitwise ---
    uint256 operator~() const {
        uint256 r;
        for (int i = 0; i < 4; ++i) r.w[i] = ~w[i];
        return r;
    }
    uint256 operator&(const uint256& o) const {
        uint256 r;
        for (int i = 0; i < 4; ++i) r.w[i] = w[i] & o.w[i];
        return r;
    }
    uint256 operator|(const uint256& o) const {
        uint256 r;
        for (int i = 0; i < 4; ++i) r.w[i] = w[i] | o.w[i];
        return r;
    }
    uint256 operator^(const uint256& o) const {
        uint256 r;
        for (int i = 0; i < 4; ++i) r.w[i] = w[i] ^ o.w[i];
        return r;
    }
    uint256& operator&=(const uint256& o) { *this = *this & o; return *this; }
    uint256& operator|=(const uint256& o) { *this = *this | o; return *this; }
    uint256& operator^=(const uint256& o) { *this = *this ^ o; return *this; }

    // --- shift ---
    uint256 operator<<(unsigned int n) const {
        if (n >= 256) return uint256();
        uint256 r;
        int wordShift = n / 64;
        int bitShift = n % 64;
        for (int i = 3; i >= 0; --i) {
            int src = i - wordShift;
            if (src < 0) { r.w[i] = 0; continue; }
            r.w[i] = w[src] << bitShift;
            if (bitShift != 0 && src - 1 >= 0)
                r.w[i] |= w[src - 1] >> (64 - bitShift);
        }
        return r;
    }
    uint256 operator>>(unsigned int n) const {
        if (n >= 256) return uint256();
        uint256 r;
        int wordShift = n / 64;
        int bitShift = n % 64;
        for (int i = 0; i < 4; ++i) {
            int src = i + wordShift;
            if (src >= 4) { r.w[i] = 0; continue; }
            r.w[i] = w[src] >> bitShift;
            if (bitShift != 0 && src + 1 < 4)
                r.w[i] |= w[src + 1] << (64 - bitShift);
        }
        return r;
    }
    uint256& operator<<=(unsigned int n) { *this = *this << n; return *this; }
    uint256& operator>>=(unsigned int n) { *this = *this >> n; return *this; }

    // --- aritmetika ---
    uint256 operator+(const uint256& o) const {
        uint256 r;
        unsigned __int128 carry = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned __int128 s = (unsigned __int128)w[i] + o.w[i] + carry;
            r.w[i] = (uint64_t)s;
            carry = s >> 64;
        }
        return r;
    }
    uint256& operator+=(const uint256& o) { *this = *this + o; return *this; }

    uint256 operator-(const uint256& o) const {
        uint256 r;
        unsigned __int128 borrow = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned __int128 d = (unsigned __int128)w[i] - o.w[i] - borrow;
            r.w[i] = (uint64_t)d;
            borrow = (w[i] < o.w[i] + borrow) ? 1 : 0;
        }
        return r;
    }
    uint256& operator-=(const uint256& o) { *this = *this - o; return *this; }

    // perkalian dengan uint64 (hasil bisa overflow 256-bit -> dipotong)
    uint256 mul64(uint64_t m) const {
        uint256 r;
        unsigned __int128 carry = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned __int128 p = (unsigned __int128)w[i] * m + carry;
            r.w[i] = (uint64_t)p;
            carry = p >> 64;
        }
        return r;
    }

    // pembagian dengan uint64
    uint256 div64(uint64_t d, uint64_t* rem = nullptr) const {
        uint256 r;
        unsigned __int128 acc = 0;
        for (int i = 3; i >= 0; --i) {
            acc = (acc << 64) | w[i];
            r.w[i] = (uint64_t)(acc / d);
            acc %= d;
        }
        if (rem) *rem = (uint64_t)acc;
        return r;
    }

    // pembagian 256-bit / 256-bit (unsigned). Asumsi: divisor != 0.
    uint256 div(const uint256& d) const {
        if (d.isZero()) return uint256();
        if (*this < d) return uint256();
        uint256 q;      // hasil
        uint256 rem;    // sisa
        for (int bit = 255; bit >= 0; --bit) {
            rem = rem << 1;
            if (bitTest(bit)) {
                rem.w[0] |= 1;
            }
            if (rem >= d) {
                rem -= d;
                q.setBit(bit);
            }
        }
        return q;
    }

    // --- bit helpers ---
    bool bitTest(unsigned int n) const {
        return (w[n / 64] >> (n % 64)) & 1;
    }
    void setBit(unsigned int n) {
        w[n / 64] |= (1ull << (n % 64));
    }
    // posisi bit tertinggi yang diset; -1 bila nol
    int highestBit() const {
        for (int i = 3; i >= 0; --i) {
            if (w[i] != 0) {
                for (int b = 63; b >= 0; --b)
                    if ((w[i] >> b) & 1) return i * 64 + b;
            }
        }
        return -1;
    }
    int getBitLength() const { return highestBit() + 1; }

    // --- compact (bits) encoding, bitcoin-style ---
    uint32_t getCompact() const;
    static uint256 setCompact(uint32_t nCompact);

    // --- byte representation: LITTLE-ENDIAN (bitcoin hash order) ---
    void setBytesLE(const uint8_t* p) {
        for (int i = 0; i < 4; ++i) {
            uint64_t v = 0;
            for (int j = 0; j < 8; ++j)
                v |= (uint64_t)p[i * 8 + j] << (8 * j);
            w[i] = v;
        }
    }
    void getBytesLE(uint8_t* p) const {
        for (int i = 0; i < 4; ++i) {
            uint64_t v = w[i];
            for (int j = 0; j < 8; ++j) {
                p[i * 8 + j] = (uint8_t)(v & 0xff);
                v >>= 8;
            }
        }
    }
    // big-endian (untuk display): p[0] = byte paling signifikan
    void getBytesBE(uint8_t* p) const {
        for (int i = 0; i < 32; ++i) {
            int wordIdx = 3 - i / 8;
            int shift = 56 - 8 * (i % 8);
            p[i] = (uint8_t)(w[wordIdx] >> shift);
        }
    }
    std::string getHex() const {
        static const char* H = "0123456789abcdef";
        std::string s(64, '0');
        for (int i = 0; i < 4; ++i) {
            uint64_t v = w[i];
            for (int j = 0; j < 8; ++j) {
                int b = i * 8 + j;      // byte ke-b dari LSB
                int pos = (31 - b) * 2; // posisi char high nibble (display MSB-first)
                s[pos] = H[(v >> 4) & 0xf];
                s[pos + 1] = H[v & 0xf];
                v >>= 8;
            }
        }
        return s;
    }
    // parse hex string (64 digit, big-endian display order)
    static uint256 fromHex(const std::string& hex);
    // parse hex string dengan urutan byte terbalik (untuk hash display)
    static uint256 fromHexReversed(const std::string& hex);

    // chain work: 2^256 / (target+1)
    static uint256 chainWorkOfTarget(const uint256& target) {
        uint256 n = target + uint256(1);
        // 2^256 direpresentasikan sebagai 1 << 256: bagi bitwise
        return pow2_256_div(n);
    }

private:
    static uint256 pow2_256_div(const uint256& d) {
        // hitung floor(2^256 / d) via shift-and-subtract pada 257-bit dividen
        if (d.isZero()) return uint256();
        uint256 q, rem;
        // kita bagi 2^256: proses bit dari 256 (1) turun ke 0
        // rem mulai 0; pada iterasi bit=256, rem = rem<<1 | bit(2^256)=1
        // sederhanakan: mulakan rem = 1 (bit 256), lalu proses bit 255..0 dengan bit 0
        rem = uint256(1);
        for (int bit = 255; bit >= 0; --bit) {
            rem = rem << 1; // bit 255..0 semuanya 0
            if (rem >= d) {
                rem -= d;
                q.setBit(bit);
            }
        }
        return q;
    }
};

using uint256_t = uint256;

// representasi 160-bit hash (untuk alamat)
class uint160 {
public:
    uint64_t w[3]; // 192 bit digunakan 160

    uint160() { clear(); }
    void clear() { std::memset(w, 0, sizeof(w)); }
    bool isZero() const { return (w[0] | w[1] | w[2]) == 0; }
    bool operator==(const uint160& o) const {
        return w[0] == o.w[0] && w[1] == o.w[1] && w[2] == o.w[2];
    }
    bool operator!=(const uint160& o) const { return !(*this == o); }
    void setBytes(const uint8_t* p) { // big-endian 20 byte
        uint64_t v0 = 0, v1 = 0, v2 = 0;
        for (int i = 0; i < 20; ++i) {
            if (i < 8) v2 = (v2 << 8) | p[i];
            else if (i < 16) v1 = (v1 << 8) | p[i];
            else v0 = (v0 << 8) | p[i];
        }
        w[0] = v0; w[1] = v1; w[2] = v2;
    }
    void getBytes(uint8_t* p) const { // big-endian 20 byte
        uint64_t v0 = w[0], v1 = w[1], v2 = w[2];
        for (int i = 19; i >= 0; --i) {
            if (i >= 16) { p[i] = (uint8_t)(v0 & 0xff); v0 >>= 8; }
            else if (i >= 8) { p[i] = (uint8_t)(v1 & 0xff); v1 >>= 8; }
            else { p[i] = (uint8_t)(v2 & 0xff); v2 >>= 8; }
        }
    }
    std::string getHex() const {
        uint8_t b[20];
        getBytes(b);
        static const char* H = "0123456789abcdef";
        std::string s(40, '0');
        for (int i = 0; i < 20; ++i) {
            s[i * 2] = H[b[i] >> 4];
            s[i * 2 + 1] = H[b[i] & 0xf];
        }
        return s;
    }
};

} // namespace cdx
