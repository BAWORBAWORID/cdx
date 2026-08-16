#pragma once
#include <cstdint>
#include <vector>
#include "transaction/transaction.h"
#include "crypto/uint256.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Serialization deterministik (bitcoin-style).
// Semua integer little-endian; varint untuk count; bytes verbatim.
// ---------------------------------------------------------------------------

class CSerializer {
public:
    std::vector<uint8_t> buf;

    CSerializer& WriteBytes(const uint8_t* p, size_t n) {
        buf.insert(buf.end(), p, p + n);
        return *this;
    }
    CSerializer& WriteU8(uint8_t v) { buf.push_back(v); return *this; }
    CSerializer& WriteU16(uint16_t v) {
        buf.push_back((uint8_t)v);
        buf.push_back((uint8_t)(v >> 8));
        return *this;
    }
    CSerializer& WriteU32(uint32_t v) {
        for (int i = 0; i < 4; ++i) buf.push_back((uint8_t)(v >> (8 * i)));
        return *this;
    }
    CSerializer& WriteU64(uint64_t v) {
        for (int i = 0; i < 8; ++i) buf.push_back((uint8_t)(v >> (8 * i)));
        return *this;
    }
    CSerializer& WriteVarInt(uint64_t v) {
        if (v < 0xfd) return WriteU8((uint8_t)v);
        if (v <= 0xffff) return WriteU8(0xfd), WriteU16((uint16_t)v), *this;
        if (v <= 0xffffffffull) return WriteU8(0xfe), WriteU32((uint32_t)v), *this;
        return WriteU8(0xff), WriteU64(v), *this;
    }
    CSerializer& WriteVarStr(const std::vector<uint8_t>& v) {
        WriteVarInt(v.size());
        return WriteBytes(v.data(), v.size());
    }
    CSerializer& WriteBytes(const std::vector<uint8_t>& v) {
        return WriteBytes(v.data(), v.size());
    }
    CSerializer& WriteUint256(const uint256& h) {
        uint8_t b[32];
        h.getBytesLE(b);
        return WriteBytes(b, 32);
    }
};

// Deserializer dengan bounds checking
class CDeserializer {
public:
    const uint8_t* p;
    size_t len;
    size_t pos = 0;

    CDeserializer(const uint8_t* data, size_t n) : p(data), len(n) {}

    bool ReadBytes(uint8_t* out, size_t n) {
        if (pos + n > len) return false;
        std::memcpy(out, p + pos, n);
        pos += n;
        return true;
    }
    bool ReadU8(uint8_t& v) { return ReadBytes(&v, 1); }
    bool ReadU16(uint16_t& v) {
        uint8_t b[2];
        if (!ReadBytes(b, 2)) return false;
        v = (uint16_t)(b[0] | (b[1] << 8));
        return true;
    }
    bool ReadU32(uint32_t& v) {
        uint8_t b[4];
        if (!ReadBytes(b, 4)) return false;
        v = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
        return true;
    }
    bool ReadU64(uint64_t& v) {
        uint8_t b[8];
        if (!ReadBytes(b, 8)) return false;
        v = 0;
        for (int i = 0; i < 8; ++i) v |= (uint64_t)b[i] << (8 * i);
        return true;
    }
    bool ReadVarInt(uint64_t& v) {
        uint8_t first;
        if (!ReadU8(first)) return false;
        if (first < 0xfd) { v = first; return true; }
        if (first == 0xfd) { uint16_t x; return ReadU16(x) ? (v = x, true) : false; }
        if (first == 0xfe) { uint32_t x; return ReadU32(x) ? (v = x, true) : false; }
        return ReadU64(v);
    }
    bool ReadVarStr(std::vector<uint8_t>& out) {
        uint64_t n;
        if (!ReadVarInt(n)) return false;
        if (n > len - pos) return false;
        out.resize(n);
        return ReadBytes(out.data(), n);
    }
    bool ReadUint256(uint256& h) {
        uint8_t b[32];
        if (!ReadBytes(b, 32)) return false;
        h.setBytesLE(b);
        return true;
    }
    size_t remaining() const { return len - pos; }
};

// --- serialisasi transaksi ---
std::vector<uint8_t> SerializeTransaction(const CTransaction& tx);
bool DeserializeTransaction(const uint8_t* data, size_t len, CTransaction& tx);
// TXID = SHA256d(serialized tx)
uint256 GetTxID(const CTransaction& tx);
uint256 GetTxID(const std::vector<uint8_t>& serialized);

// --- serialisasi block ---
struct CBlockHeader;
std::vector<uint8_t> SerializeBlockHeader(const CBlockHeader& hdr);
bool DeserializeBlockHeader(const uint8_t* data, size_t len, CBlockHeader& hdr);
std::vector<uint8_t> SerializeBlock(const struct CBlock& blk);
bool DeserializeBlock(const uint8_t* data, size_t len, struct CBlock& blk);

} // namespace cdx
