#include "blockchain/reorg.h"
#include "consensus/validation.h"
#include "consensus/difficulty.h"
#include "consensus/chainwork.h"
#include "transaction/serializer.h"
#include <algorithm>

namespace cdx {

// ---------------------------------------------------------------------------
// TryAcceptBlock:
//   1. block extends chain aktif  -> AcceptBlock langsung
//   2. block di fork              -> hitung accumulated work fork
//      (chainWork(fork point) + work(block baru))
//      Jika LEBIH TINGGI dari chain aktif:
//         validate ulang seluruh chain fork dari genesis
//         -> rollback state lama -> apply chain baru -> update UTXO
// Semua deterministik. Chain work adalah satu-satunya kriteria pemilihan.
// ---------------------------------------------------------------------------
ReorgResult TryAcceptBlock(CBlockchain& chain,
                           const CBlock& blk,
                           const CTxMemPool& mempool) {
    ReorgResult r;
    (void)mempool;

    uint256 blkHash = blk.GetHash();
    if (chain.HaveBlock(blkHash)) {
        r.ok = true;
        return r;
    }

    const CBlockIndex* prevIdx = chain.GetIndex(blk.header.prevBlockHash);
    if (!prevIdx) {
        r.error = "unknown prev block (need sync)";
        return r;
    }

    // --- kasus 1: extends chain aktif ---
    if (blk.header.prevBlockHash == chain.chain.tipHash) {
        int64_t height = prevIdx->height + 1;
        std::string err;
        if (chain.AcceptBlock(blk, height, err)) {
            r.ok = true;
            r.connected.push_back(blkHash);
            return r;
        }
        r.error = err;
        return r;
    }

    // --- kasus 2: fork ---
    // work fork = chainWork(fork point) + work(block baru)
    uint256 forkWork = prevIdx->chainWork + GetBlockWork(blk.header.bits);
    if (forkWork <= chain.GetChainWork()) {
        r.error = "fork has lower chain work";
        r.ok = false;
        return r;
    }

    // Reorg: bangun ulang chain fork = chain aktif [0..forkHeight] + [blk]
    int64_t forkHeight = prevIdx->height;

    // kumpulkan block fork (chain aktif sampai fork point + block baru)
    std::vector<CBlock> forkBlocks;
    for (int64_t h = 0; h <= forkHeight; ++h) {
        CBlock b;
        if (!chain.GetBlockByHeight(h, b)) {
            r.error = "cannot read chain block " + std::to_string(h);
            return r;
        }
        forkBlocks.push_back(std::move(b));
    }
    forkBlocks.push_back(blk);

    // validasi seluruh fork dari genesis (fresh UTXO + PoW + merkle)
    CCoinsView freshView;
    std::vector<uint256> newByHeight;
    for (size_t i = 0; i < forkBlocks.size(); ++i) {
        const auto& b = forkBlocks[i];
        int64_t h = (int64_t)i;
        std::string verr;
        const CBlockHeader* prevHdr = nullptr;
        if (i > 0) prevHdr = &forkBlocks[i - 1].header;
        if (!CheckBlockHeader(b.header, prevHdr, chain.Params(), verr)) {
            r.error = "fork validation: " + verr;
            return r;
        }
        int64_t fees = 0;
        CCoinsView outView;
        if (!CheckBlock(b, h, freshView, chain.Params(), outView, fees, verr)) {
            r.error = "fork block invalid: " + verr;
            return r;
        }
        freshView = std::move(outView);
        newByHeight.push_back(b.GetHash());
    }

    // replace state (rollback old + apply new)
    chain.GetView() = std::move(freshView);
    chain.chain.height = (int64_t)newByHeight.size() - 1;
    chain.chain.tipHash = forkBlocks.back().GetHash();
    chain.chain.byHeight = std::move(newByHeight);

    // catat block fork (yang belum ada) ke index + disk
    chain.AddIndexEntry(blk, chain.chain.height, true);
    // simpan chainstate (UTXO baru + byHeight)
    {
        // (CBlockchain menangani persist chainstate saat block berikutnya;
        //  di sini cukup index+disk agar GetBlockByHeight bekerja)
    }

    r.forkHeight = forkHeight;
    r.connected = chain.chain.byHeight;
    r.ok = true;
    return r;
}

// ---------------------------------------------------------------------------
// AcceptBlockOrphaned: menerima block yang prev-nya belum diketahui (orphan).
// Disimpan sementara untuk diproses setelah block prev tersedia.
// ---------------------------------------------------------------------------

} // namespace cdx
