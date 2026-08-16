#include "crypto/encoding.h"
#include "crypto/hash.h"
#include <cstring>
#include <stdexcept>

namespace cdx {

const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static int base58Index(char c) {
    const char* p = std::strchr(BASE58_ALPHABET, c);
    if (!p) return -1;
    return (int)(p - BASE58_ALPHABET);
}

std::string EncodeBase58(const uint8_t* data, size_t len) {
    // hitung leading zero bytes
    size_t zeros = 0;
    while (zeros < len && data[zeros] == 0) ++zeros;

    // bignum dalam base 256 -> base 58
    std::vector<uint8_t> digits; // little-endian base58 digits
    digits.reserve(len * 138 / 100 + 1);
    std::vector<uint8_t> buf(data, data + len);
    size_t start = zeros;
    while (start < buf.size()) {
        int rem = 0;
        size_t next = buf.size();
        for (size_t i = start; i < buf.size(); ++i) {
            int acc = rem * 256 + buf[i];
            buf[i] = (uint8_t)(acc / 58);
            rem = acc % 58;
            if (buf[i] != 0 && next == buf.size()) next = i;
        }
        digits.push_back((uint8_t)rem);
        if (next == buf.size()) break; // semua digit nol -> selesai
        start = next;
    }
    std::string result;
    result.reserve(zeros + digits.size());
    result.append(zeros, BASE58_ALPHABET[0]);
    for (auto it = digits.rbegin(); it != digits.rend(); ++it)
        result.push_back(BASE58_ALPHABET[*it]);
    if (result.empty()) result.push_back(BASE58_ALPHABET[0]);
    return result;
}

std::string EncodeBase58Check(const uint8_t* data, size_t len) {
    uint8_t checksum[32];
    SHA256d(data, len, checksum);
    std::vector<uint8_t> full;
    full.reserve(len + 4);
    full.insert(full.end(), data, data + len);
    full.insert(full.end(), checksum, checksum + 4);
    return EncodeBase58(full.data(), full.size());
}

std::vector<uint8_t> DecodeBase58(const std::string& s) {
    std::vector<uint8_t> b256; // little-endian base256
    b256.reserve(s.size() * 733 / 1000 + 1);
    for (char c : s) {
        int idx = base58Index(c);
        if (idx < 0) throw std::runtime_error("Invalid base58 character");
        int carry = idx;
        for (size_t i = 0; i < b256.size(); ++i) {
            int acc = b256[i] * 58 + carry;
            b256[i] = (uint8_t)(acc & 0xff);
            carry = acc >> 8;
        }
        while (carry > 0) {
            b256.push_back((uint8_t)(carry & 0xff));
            carry >>= 8;
        }
    }
    // leading '1' -> leading zero bytes
    size_t zeros = 0;
    while (zeros < s.size() && s[zeros] == BASE58_ALPHABET[0]) ++zeros;
    std::vector<uint8_t> out;
    out.reserve(zeros + b256.size());
    out.insert(out.end(), zeros, 0);
    for (auto it = b256.rbegin(); it != b256.rend(); ++it)
        out.push_back(*it);
    return out;
}

std::vector<uint8_t> DecodeBase58Check(const std::string& s) {
    std::vector<uint8_t> full = DecodeBase58(s);
    if (full.size() < 4) throw std::runtime_error("Base58Check too short");
    size_t payloadLen = full.size() - 4;
    uint8_t checksum[32];
    SHA256d(full.data(), payloadLen, checksum);
    if (std::memcmp(checksum, full.data() + payloadLen, 4) != 0)
        throw std::runtime_error("Base58Check checksum mismatch");
    return std::vector<uint8_t>(full.begin(), full.begin() + payloadLen);
}

bool DecodeHex(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return true;
}

size_t VarIntSize(uint64_t v) {
    if (v < 0xfd) return 1;
    if (v <= 0xffff) return 3;
    if (v <= 0xffffffffull) return 5;
    return 9;
}

size_t WriteVarInt(uint8_t* out, uint64_t v) {
    if (v < 0xfd) {
        out[0] = (uint8_t)v;
        return 1;
    }
    if (v <= 0xffff) {
        out[0] = 0xfd;
        WriteU16LE(out + 1, (uint16_t)v);
        return 3;
    }
    if (v <= 0xffffffffull) {
        out[0] = 0xfe;
        WriteU32LE(out + 1, (uint32_t)v);
        return 5;
    }
    out[0] = 0xff;
    WriteU64LE(out + 1, v);
    return 9;
}

int ReadVarInt(const uint8_t* data, size_t len, uint64_t& v) {
    if (len < 1) return -1;
    uint8_t first = data[0];
    if (first < 0xfd) { v = first; return 1; }
    if (first == 0xfd) {
        if (len < 3) return -1;
        v = ReadU16LE(data + 1);
        return 3;
    }
    if (first == 0xfe) {
        if (len < 5) return -1;
        v = ReadU32LE(data + 1);
        return 5;
    }
    if (len < 9) return -1;
    v = ReadU64LE(data + 1);
    return 9;
}

} // namespace cdx
