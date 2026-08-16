#include "p2p/sync.h"
#include "transaction/serializer.h"
#include "crypto/encoding.h"

namespace cdx {

std::vector<uint8_t> BuildGetHeadersPayload(const std::vector<uint256>& locator,
                                            const uint256& hashStop) {
    CSerializer s;
    s.WriteVarInt(locator.size());
    for (const auto& h : locator) s.WriteUint256(h);
    s.WriteUint256(hashStop);
    return std::move(s.buf);
}

bool ParseGetHeadersPayload(const std::vector<uint8_t>& payload,
                            std::vector<uint256>& locator, uint256& hashStop) {
    CDeserializer d(payload.data(), payload.size());
    uint64_t n;
    if (!d.ReadVarInt(n)) return false;
    if (n > 1000) return false;
    locator.clear();
    locator.reserve(n);
    for (uint64_t i = 0; i < n; ++i) {
        uint256 h;
        if (!d.ReadUint256(h)) return false;
        locator.push_back(h);
    }
    return d.ReadUint256(hashStop);
}

bool ParseHeadersPayload(const std::vector<uint8_t>& payload, std::vector<CBlockHeader>& headers) {
    CDeserializer d(payload.data(), payload.size());
    uint64_t n;
    if (!d.ReadVarInt(n)) return false;
    if (n > 2000) return false;
    headers.clear();
    headers.reserve(n);
    for (uint64_t i = 0; i < n; ++i) {
        CBlockHeader hdr;
        if (!DeserializeBlockHeader(d.p + d.pos, d.remaining(), hdr)) return false;
        d.pos += 80;
        // tx count byte (0 untuk header-only)
        uint8_t txCount;
        if (!d.ReadU8(txCount)) return false;
        headers.push_back(hdr);
    }
    return true;
}

std::vector<uint8_t> BuildHeadersPayload(const std::vector<CBlockHeader>& headers) {
    CSerializer s;
    s.WriteVarInt(headers.size());
    for (const auto& h : headers) {
        auto ser = SerializeBlockHeader(h);
        s.WriteBytes(ser.data(), ser.size());
        s.WriteU8(0); // tx count = 0 (header only)
    }
    return std::move(s.buf);
}

std::vector<uint8_t> BuildGetBlocksPayload(const std::vector<uint256>& locator,
                                           const uint256& hashStop) {
    return BuildGetHeadersPayload(locator, hashStop);
}

bool ParseBlockPayload(const std::vector<uint8_t>& payload, CBlock& blk) {
    return DeserializeBlock(payload.data(), payload.size(), blk);
}

bool ParseTxPayload(const std::vector<uint8_t>& payload, CTransaction& tx) {
    return DeserializeTransaction(payload.data(), payload.size(), tx);
}

std::vector<uint256> BuildLocator(const std::vector<uint256>& chainHashes, int64_t tipHeight) {
    std::vector<uint256> locator;
    if (chainHashes.empty()) return locator;
    int step = 1;
    int64_t h = tipHeight;
    while (h >= 0 && locator.size() < 32) {
        locator.push_back(chainHashes[(size_t)h]);
        if (h == 0) break;
        h -= step;
        if (locator.size() > 10) step *= 2;
    }
    return locator;
}

} // namespace cdx
