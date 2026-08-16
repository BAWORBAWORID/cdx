#pragma once
#include <cstdint>
#include <atomic>
#include <string>
#include <functional>
#include "blockchain/block.h"
#include "mempool/mempool.h"
#include "utxo/utxo-set.h"
#include "config/networks.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Miner — membangun candidate block + mining.
//   Create candidate: pilih tx dari mempool, buat coinbase, merkle, header.
//   Mine: SHA256d sampai <= target.
//   Coinbase: block height + extraNonce + miner data.
// ---------------------------------------------------------------------------

struct MiningStatus {
    bool mining = false;
    uint64_t hashesPerSec = 0;
    int64_t hashCount = 0;
    int64_t lastBlockHeight = 0;
    int64_t blockReward = 0;
    std::string miningAddress;
    int64_t blocksFound = 0;
    int64_t immatureReward = 0;
    int64_t maturedReward = 0;
};

class CMiner {
public:
    std::atomic<bool> running{false};
    std::atomic<bool> stopRequested{false};

    // set alamat payout coinbase
    void SetMiningAddress(const std::string& addr, uint8_t versionByte) {
        miningAddress = addr;
        miningVersion = versionByte;
    }
    std::string GetMiningAddress() const { return miningAddress; }

    // callback saat block ditemukan (untuk broadcast & apply)
    std::function<void(const CBlock&)> onBlockFound;

    void Start();
    void Stop() { stopRequested = true; }
    bool IsRunning() const { return running.load(); }

    MiningStatus GetStatus() const;

    // bangun block (tanpa mining) — dipakai test juga
    static CBlock CreateCandidateBlock(int64_t height, uint32_t bits, uint32_t timestamp,
                                       const uint256& prevHash,
                                       const CTxMemPool& mempool,
                                       const CCoinsView& view,
                                       const std::string& minerAddress,
                                       uint8_t versionByte,
                                       int64_t& feesOut);

    void RunLoop();

    // statistik
    std::atomic<int64_t> totalHashes{0};
    std::atomic<int64_t> blocksFound{0};
    int64_t lastHeightMined = -1;
    int64_t immatureReward = 0;
    int64_t maturedReward = 0;

private:
    std::string miningAddress;
    uint8_t miningVersion = 0x1E;
};

} // namespace cdx
