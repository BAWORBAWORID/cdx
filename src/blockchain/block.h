#pragma once
#include <cstdint>
#include <vector>
#include "crypto/uint256.h"
#include "transaction/transaction.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Block header:
//   version, prevBlockHash, merkleRoot, timestamp, bits, nonce
// Hash block = SHA256d(serialized 80-byte header), interpretasi little-endian.
// Block valid jika: blockHash <= target(bits)
// ---------------------------------------------------------------------------
struct CBlockHeader {
    int32_t version = 1;
    uint256 prevBlockHash;
    uint256 merkleRoot;
    uint32_t timestamp = 0;
    uint32_t bits = 0;
    uint32_t nonce = 0;

    uint256 GetHash() const;
};

struct CBlock {
    CBlockHeader header;
    std::vector<CTransaction> vtx;

    uint256 GetHash() const { return header.GetHash(); }
    // cek merkle root cocok dengan header
    bool CheckMerkleRoot() const;
};

} // namespace cdx
