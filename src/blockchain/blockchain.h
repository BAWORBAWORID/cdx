#pragma once
#include <cstdint>
#include <map>
#include <vector>
#include <string>
#include <mutex>
#include "blockchain/block.h"
#include "utxo/utxo-set.h"
#include "mempool/mempool.h"
#include "config/networks.h"
#include "storage/interface.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Blockchain manager — source of truth: blockchain + consensus + UTXO set.
// ---------------------------------------------------------------------------

struct ChainTip {
    uint256 hash;
    int64_t height = -1;
    uint256 chainWork;
};

class CBlockIndex {
public:
    uint256 hash;
    uint256 prevHash;
    int64_t height = -1;
    uint32_t bits = 0;
    uint32_t timestamp = 0;
    uint256 chainWork;
    uint256 merkleRoot;
    bool isGenesis = false;
};

class CChain {
public:
    CCoinsView view;          // UTXO set saat tip
    std::map<uint256, CBlockIndex> index; // hash -> index
    std::vector<uint256> byHeight;        // height -> hash
    int64_t height = -1;
    uint256 tipHash;
    uint256 chainWork;

    CBlockIndex* Find(const uint256& hash) {
        auto it = index.find(hash);
        return it == index.end() ? nullptr : &it->second;
    }
    const CBlockIndex* Find(const uint256& hash) const {
        auto it = index.find(hash);
        return it == index.end() ? nullptr : &it->second;
    }
    CBlockIndex* Tip() {
        if (height < 0) return nullptr;
        return Find(byHeight[(size_t)height]);
    }
    const CBlockIndex* Tip() const {
        if (height < 0) return nullptr;
        return Find(byHeight[(size_t)height]);
    }
};

class CBlockchain {
public:
    explicit CBlockchain(const ChainParams& params, IStorage* storage);

    // inisialisasi: load dari storage atau create genesis
    bool Init(std::string& error);

    // dapatkan block dari storage (by hash / by height)
    bool GetBlock(const uint256& hash, CBlock& blk) const;
    bool GetBlockByHeight(int64_t height, CBlock& blk) const;

    // header + index
    const CBlockIndex* GetIndex(const uint256& hash) const;
    const CBlockIndex* GetTip() const;
    int64_t GetHeight() const;
    const uint256& GetTipHash() const;
    const CCoinsView& GetView() const { return chain.view; }
    CCoinsView& GetView() { return chain.view; }

    uint256 GetChainWork() const { return chain.chainWork; }

    // dapatkan header tertentu dari storage
    bool GetBlockHeader(const uint256& hash, CBlockHeader& hdr) const;

    // cari fork point antara chain aktif dan hash (untuk reorg)
    int64_t FindForkHeight(const uint256& hash) const;

    // hash block pada height tertentu di chain aktif
    bool GetBlockHashByHeight(int64_t height, uint256& hash) const {
        if (height < 0 || height > chain.height) return false;
        hash = chain.byHeight[(size_t)height];
        return true;
    }

    // apply block (validasi + update UTXO + mempool cleanup + storage)
    // Mengembalikan false bila block invalid (error berisi alasan).
    bool AcceptBlock(const CBlock& blk, int64_t height, std::string& error);

    // dipakai reorg: catat block baru ke index + simpan ke disk (tanpa re-validasi)
    void AddIndexEntry(const CBlock& blk, int64_t height, bool writeDisk);

    // verifikasi header + cek PoW + prev, tanpa modifikasi state
    bool CheckBlockHeaderOnly(const CBlockHeader& hdr, const CBlockHeader* prev,
                              std::string& error) const;

    // konteks tip untuk mining
    CBlockIndex* TipIndex();

    // konflik: apakah block sudah ada
    bool HaveBlock(const uint256& hash) const;

    // accessor mutex (untuk thread-safety P2P/mining)
    std::mutex& GetMutex() { return mutex; }

    const ChainParams& Params() const { return params; }

public:
    // state rantai (diakses reorg/modul lain; lindungi via GetMutex())
    CChain chain;

private:
    const ChainParams& params;
    IStorage* storage;
    mutable std::mutex mutex;

    bool LoadFromStorage(std::string& error);
    bool ApplyGenesis(std::string& error);
};

} // namespace cdx
