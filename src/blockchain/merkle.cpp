#include "blockchain/merkle.h"
#include "crypto/hash.h"
#include "transaction/serializer.h"

namespace cdx {

uint256 ComputeMerkleRoot(const std::vector<uint256>& hashes) {
    if (hashes.empty()) return uint256();
    std::vector<uint256> level = hashes;
    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            uint8_t buf[64];
            level[i].getBytesLE(buf);
            if (i + 1 < level.size()) level[i + 1].getBytesLE(buf + 32);
            else level[i].getBytesLE(buf + 32); // duplikasi
            uint8_t h[32];
            SHA256d(buf, 64, h);
            uint256 r;
            r.setBytesLE(h);
            next.push_back(r);
        }
        level = std::move(next);
    }
    return level[0];
}

uint256 ComputeMerkleRoot(const std::vector<CTransaction>& txs) {
    std::vector<uint256> hashes;
    hashes.reserve(txs.size());
    for (const auto& tx : txs)
        hashes.push_back(GetTxID(tx));
    return ComputeMerkleRoot(hashes);
}

} // namespace cdx
