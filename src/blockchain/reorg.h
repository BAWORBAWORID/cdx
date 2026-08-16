#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include "blockchain/block.h"
#include "blockchain/blockchain.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Chain reorganization.
// Jika chain alternatif memiliki accumulated work lebih tinggi:
//   validate alternative chain -> rollback old state -> apply new chain
//   -> update UTXO -> reprocess mempool
// Semua deterministic.
// ---------------------------------------------------------------------------

struct ReorgResult {
    bool ok = false;
    std::string error;
    int64_t forkHeight = -1;
    std::vector<uint256> disconnected;
    std::vector<uint256> connected;
};

// Coba terima block yang mungkin berada di fork.
// Mengembalikan true bila block diterima (di chain utama) ATAU
// reorg sukses dilakukan.
ReorgResult TryAcceptBlock(CBlockchain& chain,
                           const CBlock& blk,
                           const CTxMemPool& mempool);
} // namespace cdx
