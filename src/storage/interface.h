#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "crypto/uint256.h"
#include "blockchain/block.h"
#include "utxo/utxo-set.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Storage abstraction.
// Implementasi: file-based (data/blocks, data/chainstate) — mirip blk*.dat
// arsitektur early Bitcoin. LevelDB/RocksDB dapat ditambahkan nanti.
// MongoDB BUKAN consensus storage.
// ---------------------------------------------------------------------------

struct StoredBlock {
    uint256 hash;
    CBlock block;
    int64_t height = -1;
};

class IStorage {
public:
    virtual ~IStorage() = default;

    // --- blocks ---
    virtual bool WriteBlock(const CBlock& blk, int64_t height) = 0;
    virtual bool ReadBlock(const uint256& hash, CBlock& blk) = 0;
    virtual bool HasBlock(const uint256& hash) = 0;

    // --- chain state ---
    virtual bool SaveChainState(const CCoinsView& view, int64_t height,
                                const uint256& tipHash, const std::vector<uint256>& byHeight) = 0;
    virtual bool LoadChainState(CCoinsView& view, int64_t& height,
                                uint256& tipHash, std::vector<uint256>& byHeight) = 0;

    // --- peers ---
    virtual bool SavePeers(const std::vector<std::string>& addresses) = 0;
    virtual std::vector<std::string> LoadPeers() = 0;
};

} // namespace cdx
