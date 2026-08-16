#include "transaction/serializer.h"
#include "crypto/hash.h"
#include "blockchain/block.h"
#include <cstring>

namespace cdx {

std::vector<uint8_t> SerializeTransaction(const CTransaction& tx) {
    CSerializer s;
    s.WriteU32((uint32_t)tx.version);
    s.WriteVarInt(tx.vin.size());
    for (const auto& in : tx.vin) {
        s.WriteUint256(in.prevout.hash);
        s.WriteU32(in.prevout.n);
        s.WriteVarStr(in.scriptSig);
        s.WriteU32(in.sequence);
    }
    s.WriteVarInt(tx.vout.size());
    for (const auto& out : tx.vout) {
        s.WriteU64((uint64_t)out.value);
        s.WriteVarStr(out.scriptPubKey);
    }
    s.WriteU32(tx.lockTime);
    return std::move(s.buf);
}

bool DeserializeTransaction(const uint8_t* data, size_t len, CTransaction& tx) {
    CDeserializer d(data, len);
    uint32_t ver;
    if (!d.ReadU32(ver)) return false;
    tx.version = (int32_t)ver;
    uint64_t nvin;
    if (!d.ReadVarInt(nvin)) return false;
    if (nvin > 100000) return false;
    tx.vin.clear();
    tx.vin.reserve(nvin);
    for (uint64_t i = 0; i < nvin; ++i) {
        CTxIn in;
        if (!d.ReadUint256(in.prevout.hash)) return false;
        if (!d.ReadU32(in.prevout.n)) return false;
        if (!d.ReadVarStr(in.scriptSig)) return false;
        if (!d.ReadU32(in.sequence)) return false;
        tx.vin.push_back(std::move(in));
    }
    uint64_t nvout;
    if (!d.ReadVarInt(nvout)) return false;
    if (nvout > 100000) return false;
    tx.vout.clear();
    tx.vout.reserve(nvout);
    for (uint64_t i = 0; i < nvout; ++i) {
        CTxOut out;
        uint64_t v;
        if (!d.ReadU64(v)) return false;
        out.value = (int64_t)v;
        if (!d.ReadVarStr(out.scriptPubKey)) return false;
        tx.vout.push_back(std::move(out));
    }
    if (!d.ReadU32(tx.lockTime)) return false;
    return true;
}

uint256 GetTxID(const CTransaction& tx) {
    auto ser = SerializeTransaction(tx);
    return SHA256d(ser.data(), ser.size());
}

uint256 GetTxID(const std::vector<uint8_t>& serialized) {
    return SHA256d(serialized.data(), serialized.size());
}

std::vector<uint8_t> SerializeBlockHeader(const CBlockHeader& hdr) {
    CSerializer s;
    s.WriteU32((uint32_t)hdr.version);
    s.WriteUint256(hdr.prevBlockHash);
    s.WriteUint256(hdr.merkleRoot);
    s.WriteU32(hdr.timestamp);
    s.WriteU32(hdr.bits);
    s.WriteU32(hdr.nonce);
    return std::move(s.buf);
}

bool DeserializeBlockHeader(const uint8_t* data, size_t len, CBlockHeader& hdr) {
    CDeserializer d(data, len);
    uint32_t ver;
    if (!d.ReadU32(ver)) return false;
    hdr.version = (int32_t)ver;
    if (!d.ReadUint256(hdr.prevBlockHash)) return false;
    if (!d.ReadUint256(hdr.merkleRoot)) return false;
    if (!d.ReadU32(hdr.timestamp)) return false;
    if (!d.ReadU32(hdr.bits)) return false;
    if (!d.ReadU32(hdr.nonce)) return false;
    return true;
}

std::vector<uint8_t> SerializeBlock(const CBlock& blk) {
    CSerializer s;
    auto hdrSer = SerializeBlockHeader(blk.header);
    s.WriteBytes(hdrSer.data(), hdrSer.size());
    s.WriteVarInt(blk.vtx.size());
    for (const auto& tx : blk.vtx) {
        auto txSer = SerializeTransaction(tx);
        s.WriteBytes(txSer.data(), txSer.size());
    }
    return std::move(s.buf);
}

bool DeserializeBlock(const uint8_t* data, size_t len, CBlock& blk) {
    CDeserializer d(data, len);
    if (!DeserializeBlockHeader(data, len, blk.header)) return false;
    d.pos = 80;
    uint64_t ntx;
    if (!d.ReadVarInt(ntx)) return false;
    if (ntx > 100000) return false;
    blk.vtx.clear();
    blk.vtx.reserve(ntx);
    for (uint64_t i = 0; i < ntx; ++i) {
        CTransaction tx;
        if (!DeserializeTransaction(d.p + d.pos, d.remaining(), tx)) return false;
        d.pos += SerializeTransaction(tx).size();
        blk.vtx.push_back(std::move(tx));
    }
    return true;
}

} // namespace cdx
