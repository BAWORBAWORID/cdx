#include "blockchain/blockchain.h"
#include "blockchain/genesis.h"
#include "blockchain/reorg.h"
#include "consensus/validation.h"
#include "consensus/difficulty.h"
#include "consensus/chainwork.h"
#include "transaction/serializer.h"
#include "crypto/hash.h"
#include <algorithm>

namespace cdx {

CBlockchain::CBlockchain(const ChainParams& params, IStorage* storage)
    : params(params), storage(storage) {}

bool CBlockchain::Init(std::string& error) {
    if (!LoadFromStorage(error)) return false;
    return true;
}

bool CBlockchain::LoadFromStorage(std::string& error) {
    // load chainstate
    int64_t h = -1;
    uint256 tip;
    std::vector<uint256> byHeight;
    if (storage->LoadChainState(chain.view, h, tip, byHeight)) {
        chain.height = h;
        chain.tipHash = tip;
        chain.byHeight = byHeight;
        // rebuild index dari blocks
        for (size_t i = 0; i < byHeight.size(); ++i) {
            CBlock blk;
            if (!storage->ReadBlock(byHeight[i], blk)) continue;
            CBlockIndex idx;
            idx.hash = blk.GetHash();
            idx.prevHash = blk.header.prevBlockHash;
            idx.height = (int64_t)i;
            idx.bits = blk.header.bits;
            idx.timestamp = blk.header.timestamp;
            idx.merkleRoot = blk.header.merkleRoot;
            idx.chainWork = i == 0 ? GetBlockWork(blk.header.bits)
                                   : chain.index[blk.header.prevBlockHash].chainWork + GetBlockWork(blk.header.bits);
            idx.isGenesis = (i == 0);
            chain.index[idx.hash] = idx;
        }
        if (!chain.index.empty()) {
            chain.chainWork = chain.index[tip].chainWork;
            return true;
        }
    }
    // genesis
    return ApplyGenesis(error);
}

bool CBlockchain::ApplyGenesis(std::string& error) {
    CBlock genesis;
    try {
        genesis = GetGenesisBlock(params);
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    // mine genesis (nonce search) jika hash belum sesuai target
    // (untuk mainnet/testnet, nonce sudah di-set via scripts/genesis)
    // validasi header
    std::string verr;
    if (!CheckBlockHeader(genesis.header, nullptr, params, verr)) {
        // coba mine ulang genesis dengan nonce search
        bool found = false;
        for (uint32_t nonce = 0; nonce < 0xffffffffu; ++nonce) {
            genesis.header.nonce = nonce;
            if (CheckProofOfWork(genesis.header.GetHash(), genesis.header.bits)) {
                found = true;
                break;
            }
        }
        if (!found) {
            error = "could not mine genesis block";
            return false;
        }
    }

    // apply genesis: UTXO coinbase
    chain.view = CCoinsView();
    int64_t fees = 0;
    CCoinsView outView;
    if (!CheckBlock(genesis, 0, chain.view, params, outView, fees, verr)) {
        error = "genesis validation failed: " + verr;
        return false;
    }
    chain.view = std::move(outView);
    chain.height = 0;
    chain.tipHash = genesis.GetHash();
    chain.byHeight.clear();
    chain.byHeight.push_back(chain.tipHash);
    CBlockIndex idx;
    idx.hash = chain.tipHash;
    idx.prevHash.clear();
    idx.height = 0;
    idx.bits = genesis.header.bits;
    idx.timestamp = genesis.header.timestamp;
    idx.merkleRoot = genesis.header.merkleRoot;
    idx.chainWork = GetBlockWork(genesis.header.bits);
    idx.isGenesis = true;
    chain.index[idx.hash] = idx;
    chain.chainWork = idx.chainWork;

    storage->WriteBlock(genesis, 0);
    storage->SaveChainState(chain.view, chain.height, chain.tipHash, chain.byHeight);
    return true;
}

bool CBlockchain::GetBlock(const uint256& hash, CBlock& blk) const {
    return storage->ReadBlock(hash, blk);
}

bool CBlockchain::GetBlockByHeight(int64_t height, CBlock& blk) const {
    if (height < 0 || height > chain.height) return false;
    return storage->ReadBlock(chain.byHeight[(size_t)height], blk);
}

const CBlockIndex* CBlockchain::GetIndex(const uint256& hash) const {
    auto it = chain.index.find(hash);
    return it == chain.index.end() ? nullptr : &it->second;
}

const CBlockIndex* CBlockchain::GetTip() const { return chain.Tip(); }

int64_t CBlockchain::GetHeight() const { return chain.height; }

const uint256& CBlockchain::GetTipHash() const { return chain.tipHash; }

bool CBlockchain::GetBlockHeader(const uint256& hash, CBlockHeader& hdr) const {
    CBlock blk;
    if (!storage->ReadBlock(hash, blk)) return false;
    hdr = blk.header;
    return true;
}

int64_t CBlockchain::FindForkHeight(const uint256& hash) const {
    const CBlockIndex* idx = GetIndex(hash);
    if (!idx) return -1;
    int64_t h = idx->height;
    if (h > chain.height) h = chain.height;
    uint256 cur = hash;
    while (h >= 0) {
        if (chain.byHeight[(size_t)h] == cur) return h;
        cur = idx->prevHash;
        idx = GetIndex(cur);
        if (!idx) return -1;
        h = idx->height;
    }
    return -1;
}

bool CBlockchain::HaveBlock(const uint256& hash) const {
    return chain.index.count(hash) > 0;
}

bool CBlockchain::CheckBlockHeaderOnly(const CBlockHeader& hdr, const CBlockHeader* prev,
                                       std::string& error) const {
    return CheckBlockHeader(hdr, prev, params, error);
}

CBlockIndex* CBlockchain::TipIndex() { return chain.Tip(); }

void CBlockchain::AddIndexEntry(const CBlock& blk, int64_t height, bool writeDisk) {
    uint256 hash = blk.GetHash();
    const CBlockIndex* prev = GetIndex(blk.header.prevBlockHash);
    CBlockIndex idx;
    idx.hash = hash;
    idx.prevHash = blk.header.prevBlockHash;
    idx.height = height;
    idx.bits = blk.header.bits;
    idx.timestamp = blk.header.timestamp;
    idx.merkleRoot = blk.header.merkleRoot;
    idx.chainWork = (prev ? prev->chainWork : uint256()) + GetBlockWork(blk.header.bits);
    idx.isGenesis = (height == 0);
    chain.index[hash] = idx;
    if (writeDisk) storage->WriteBlock(blk, height);
}

bool CBlockchain::AcceptBlock(const CBlock& blk, int64_t height, std::string& error) {
    // validasi header
    CBlockHeader prevHdr;
    const CBlockIndex* prevIdx = GetIndex(blk.header.prevBlockHash);
    if (!prevIdx) {
        error = "unknown prev block";
        return false;
    }
    CBlockHeader prev;
    prev = blk.header; // placeholder
    // ambil prev header dari storage
    {
        CBlock prevBlk;
        if (!storage->ReadBlock(blk.header.prevBlockHash, prevBlk)) {
            error = "cannot read prev block";
            return false;
        }
        prev = prevBlk.header;
    }
    if (!CheckBlockHeader(blk.header, &prev, params, error)) return false;

    // validasi difficulty (bits harus sesuai perhitungan node)
    // bits = next work required berdasar prev chain
    {
        // ambil interval start time
        int64_t firstTime = prev.timestamp;
        int64_t intervalStartHeight = (prevIdx->height + 1) / params.difficultyInterval * params.difficultyInterval;
        if (intervalStartHeight > 0) {
            CBlock firstBlk;
            if (storage->ReadBlock(chain.byHeight[(size_t)intervalStartHeight], firstBlk))
                firstTime = firstBlk.header.timestamp;
        }
        uint32_t expectedBits = GetNextWorkRequired(prev.timestamp, prevIdx->height,
                                                    prev.bits, firstTime, params);
        if (blk.header.bits != expectedBits) {
            error = "incorrect difficulty bits";
            return false;
        }
    }

    // validasi penuh block terhadap UTXO view
    int64_t fees = 0;
    CCoinsView newView;
    if (!CheckBlock(blk, height, chain.view, params, newView, fees, error)) return false;

    // apply
    chain.view = std::move(newView);
    chain.height = height;
    chain.tipHash = blk.GetHash();
    chain.byHeight.push_back(blk.GetHash());
    CBlockIndex idx;
    idx.hash = blk.GetHash();
    idx.prevHash = blk.header.prevBlockHash;
    idx.height = height;
    idx.bits = blk.header.bits;
    idx.timestamp = blk.header.timestamp;
    idx.merkleRoot = blk.header.merkleRoot;
    idx.chainWork = prevIdx->chainWork + GetBlockWork(blk.header.bits);
    idx.isGenesis = false;
    chain.index[idx.hash] = idx;
    chain.chainWork = idx.chainWork;

    storage->WriteBlock(blk, height);
    storage->SaveChainState(chain.view, chain.height, chain.tipHash, chain.byHeight);
    return true;
}

} // namespace cdx
