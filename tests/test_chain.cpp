#include "testfw.h"
#include "blockchain/blockchain.h"
#include "blockchain/reorg.h"
#include "blockchain/genesis.h"
#include "blockchain/merkle.h"
#include "storage/blocks.h"
#include "consensus/validation.h"
#include "consensus/difficulty.h"
#include "consensus/rewards.h"
#include "consensus/difficulty.h"
#include "transaction/serializer.h"
#include "script/interpreter.h"
#include "mining/pow.h"
#include <filesystem>

using namespace cdx;

// regtest genesis params
static CBlock MakeRegtestBlock(const uint256& prev, int64_t height, uint32_t ts,
                               const std::vector<CTransaction>& txs = {}) {
    CBlock blk;
    CTransaction cb;
    cb.version = 1;
    CTxIn in;
    in.prevout.hash.clear();
    in.prevout.n = 0xffffffff;
    std::vector<uint8_t> sig;
    sig.push_back(0x04);
    sig.push_back((uint8_t)(height & 0xff));
    sig.push_back((uint8_t)((height >> 8) & 0xff));
    sig.push_back(0x00);
    sig.push_back(0x00);
    in.scriptSig = sig;
    cb.vin.push_back(in);
    CTxOut out;
    out.value = GetBlockSubsidy(height);
    out.scriptPubKey = {0x51};
    cb.vout.push_back(out);
    blk.vtx.push_back(cb);
    for (const auto& t : txs) blk.vtx.push_back(t);
    blk.header.version = 1;
    blk.header.prevBlockHash = prev;
    blk.header.merkleRoot = ComputeMerkleRoot(blk.vtx);
    blk.header.timestamp = ts;
    blk.header.bits = REGTEST_TARGET_BITS;
    return blk;
}

static bool MineRegtest(CBlock& blk) {
    return MineBlockHeader(blk.header, REGTEST_TARGET_BITS, nullptr);
}

// genesis timestamp CDX = 1717200000; block berikutnya harus lebih baru
static constexpr uint32_t GENESIS_TS = 1717200000;

TEST(chain_genesis_init) {
    std::string dir = "/tmp/cdx-test-chain1";
    std::filesystem::remove_all(dir);
    CBlockStorage storage(dir);
    CBlockchain chain(RegtestParams(), &storage);
    std::string error;
    CHECK(chain.Init(error));
    CHECK(chain.GetHeight() == 0);
    CHECK(!chain.GetTipHash().isZero());
    CHECK(chain.GetView().Size() == 1); // coinbase genesis
    // genesis hash harus konsisten
    CBlock g;
    CHECK(chain.GetBlockByHeight(0, g));
    CHECK(g.GetHash() == chain.GetTipHash());
    std::filesystem::remove_all(dir);
}

TEST(chain_accept_blocks) {
    std::string dir = "/tmp/cdx-test-chain2";
    std::filesystem::remove_all(dir);
    CBlockStorage storage(dir);
    CBlockchain chain(RegtestParams(), &storage);
    std::string error;
    CHECK(chain.Init(error));

    // mine 10 block
    for (int i = 1; i <= 10; ++i) {
        CBlock blk = MakeRegtestBlock(chain.GetTipHash(), i, GENESIS_TS + (uint32_t)i);
        CHECK(MineRegtest(blk));
        CHECK(chain.AcceptBlock(blk, i, error));
        CHECK(error.empty());
        CHECK(chain.GetHeight() == i);
    }
    // chain work bertambah
    CHECK(!chain.GetChainWork().isZero());
    // block salah prev -> reject
    CBlock bad = MakeRegtestBlock(uint256(0xdead), 11, 2000);
    CHECK(MineRegtest(bad));
    CHECK(!chain.AcceptBlock(bad, 11, error));
    CHECK(!error.empty());
    std::filesystem::remove_all(dir);
}

TEST(chain_utxo_after_blocks) {
    std::string dir = "/tmp/cdx-test-chain3";
    std::filesystem::remove_all(dir);
    CBlockStorage storage(dir);
    CBlockchain chain(RegtestParams(), &storage);
    std::string error;
    CHECK(chain.Init(error));

    // 121 block coinbase (genesis + 120) -> coinbase genesis mature
    for (int i = 1; i <= 121; ++i) {
        CBlock blk = MakeRegtestBlock(chain.GetTipHash(), i, GENESIS_TS + (uint32_t)i);
        CHECK(MineRegtest(blk));
        CHECK(chain.AcceptBlock(blk, i, error));
    }
    CHECK(chain.GetHeight() == 121);
    // semua coinbase UTXO ada
    CHECK(chain.GetView().Size() == 122);
    // total value = sum subsidy height 0..121
    int64_t expected = 0;
    for (int64_t h = 0; h <= 121; ++h) expected += GetBlockSubsidy(h);
    CHECK(chain.GetView().TotalValue() == expected);
    std::filesystem::remove_all(dir);
}

TEST(chain_merkle_reject) {
    std::string dir = "/tmp/cdx-test-chain4";
    std::filesystem::remove_all(dir);
    CBlockStorage storage(dir);
    CBlockchain chain(RegtestParams(), &storage);
    std::string error;
    CHECK(chain.Init(error));
    CBlock blk = MakeRegtestBlock(chain.GetTipHash(), 1, GENESIS_TS + 1);
    CHECK(MineRegtest(blk));
    // rusak merkle root
    blk.header.merkleRoot = uint256(0xbad);
    CHECK(!chain.AcceptBlock(blk, 1, error));
    CHECK(!error.empty());
    std::filesystem::remove_all(dir);
}

TEST(chain_reorg_lower_work_rejected) {
    std::string dir = "/tmp/cdx-test-chain5";
    std::filesystem::remove_all(dir);
    CBlockStorage storage(dir);
    CBlockchain chain(RegtestParams(), &storage);
    std::string error;
    CHECK(chain.Init(error));
    // chain utama: 5 block
    std::vector<CBlock> mainBlocks;
    for (int i = 1; i <= 5; ++i) {
        CBlock blk = MakeRegtestBlock(chain.GetTipHash(), i, GENESIS_TS + (uint32_t)i);
        CHECK(MineRegtest(blk));
        CHECK(chain.AcceptBlock(blk, i, error));
        mainBlocks.push_back(blk);
    }
    // fork pendek dari genesis (1 block saja) — work lebih rendah
    uint256 genesisHash;
    chain.GetBlockHashByHeight(0, genesisHash);
    CBlock fork = MakeRegtestBlock(genesisHash, 1, GENESIS_TS + 100);
    CHECK(MineRegtest(fork));
    ReorgResult r = TryAcceptBlock(chain, fork, CTxMemPool());
    CHECK(!r.ok); // fork work lebih rendah
    CHECK(chain.GetHeight() == 5);
    std::filesystem::remove_all(dir);
}

TEST(chain_reorg_higher_work) {
    std::string dir = "/tmp/cdx-test-chain6";
    std::filesystem::remove_all(dir);
    CBlockStorage storage(dir);
    CBlockchain chain(RegtestParams(), &storage);
    std::string error;
    CHECK(chain.Init(error));
    // chain A: 3 block (height 1..3)
    for (int i = 1; i <= 3; ++i) {
        CBlock blk = MakeRegtestBlock(chain.GetTipHash(), i, GENESIS_TS + (uint32_t)i);
        CHECK(MineRegtest(blk));
        CHECK(chain.AcceptBlock(blk, i, error));
    }
    uint256 forkPoint = chain.GetTipHash();

    // chain B: fork dari block 3, 4 block baru (b1..b4)
    // fork total = 3 + 4 = 7 block > chain A (3 block) -> reorg
    CBlock b1 = MakeRegtestBlock(forkPoint, 4, GENESIS_TS + 100);
    CHECK(MineRegtest(b1));
    CBlock b2 = MakeRegtestBlock(b1.GetHash(), 5, GENESIS_TS + 101);
    CHECK(MineRegtest(b2));
    CBlock b3 = MakeRegtestBlock(b2.GetHash(), 6, GENESIS_TS + 102);
    CHECK(MineRegtest(b3));
    CBlock b4 = MakeRegtestBlock(b3.GetHash(), 7, GENESIS_TS + 103);
    CHECK(MineRegtest(b4));

    // 1) b1: prev = block 3 (fork point di chain aktif) -> fork
    //    work fork = chainWork(3) + work(b1) = 4 block > 3 block chain A
    //    -> reorg: chain baru = [0..3] + [b1], height 4
    ReorgResult r1 = TryAcceptBlock(chain, b1, CTxMemPool());
    CHECK(r1.ok);
    CHECK(chain.GetHeight() == 4);
    CHECK(chain.GetTipHash() == b1.GetHash());

    // 2) b2..b4 extends chain baru (prev = tip) -> accept biasa
    CHECK(TryAcceptBlock(chain, b2, CTxMemPool()).ok);
    CHECK(chain.GetHeight() == 5);
    CHECK(TryAcceptBlock(chain, b3, CTxMemPool()).ok);
    CHECK(chain.GetHeight() == 6);
    CHECK(TryAcceptBlock(chain, b4, CTxMemPool()).ok);
    CHECK(chain.GetHeight() == 7);
    CHECK(chain.GetTipHash() == b4.GetHash());

    // UTXO di chain baru: coinbase height 0..7 ada
    int64_t expected = 0;
    for (int64_t h = 0; h <= 7; ++h) expected += GetBlockSubsidy(h);
    CHECK(chain.GetView().TotalValue() == expected);
    std::filesystem::remove_all(dir);
}
