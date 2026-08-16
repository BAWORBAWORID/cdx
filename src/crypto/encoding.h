#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace cdx {

// ---------------------------------------------------------------------------
// Encoding: Base58Check, hex, varint (CompactSize), string serializer.
// ---------------------------------------------------------------------------

// Base58 alphabet standar (Bitcoin)
extern const char* BASE58_ALPHABET;

// Encode Base58 polos
std::string EncodeBase58(const uint8_t* data, size_t len);

// Encode Base58Check: data || SHA256d(data)[0:4]
std::string EncodeBase58Check(const uint8_t* data, size_t len);

// Decode Base58Check; mengembalikan payload tanpa checksum.
// Melempar std::runtime_error bila checksum invalid / format salah.
std::vector<uint8_t> DecodeBase58Check(const std::string& s);

// Decode Base58 polos (tanpa checksum)
std::vector<uint8_t> DecodeBase58(const std::string& s);

// hex decode; mengembalikan false bila format invalid
bool DecodeHex(const std::string& hex, std::vector<uint8_t>& out);

// --- varint / CompactSize (bitcoin serialize style) ---
// ukuran serialized varint
size_t VarIntSize(uint64_t v);
// tulis varint ke buffer; mengembalikan jumlah byte ditulis
size_t WriteVarInt(uint8_t* out, uint64_t v);
// baca varint; mengembalikan jumlah byte dibaca; -1 bila invalid
int ReadVarInt(const uint8_t* data, size_t len, uint64_t& v);

// --- helper small-endian ---
inline void WriteU16LE(uint8_t* out, uint16_t v) {
    out[0] = (uint8_t)v; out[1] = (uint8_t)(v >> 8);
}
inline void WriteU32LE(uint8_t* out, uint32_t v) {
    out[0] = (uint8_t)v; out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16); out[3] = (uint8_t)(v >> 24);
}
inline void WriteU64LE(uint8_t* out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out[i] = (uint8_t)(v >> (8 * i));
}
inline uint32_t ReadU32LE(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline uint64_t ReadU64LE(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (8 * i);
    return v;
}
inline uint16_t ReadU16LE(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

} // namespace cdx
