#include <cstdio>
#include <filesystem>
#include "storage/blocks.h"
#include "blockchain/blockchain.h"
#include "blockchain/merkle.h"
#include "blockchain/genesis.h"
#include "consensus/rewards.h"
#include "consensus/difficulty.h"
#include "mining/pow.h"
#include "transaction/serializer.h"
#include "crypto/hash.h"
using namespace cdx;

static CBlock MakeRegtestBlock(const uint256& prev, int64_t height, uint32_t ts) {
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
    blk.header.version = 1;
    blk.header.prevBlockHash = prev;
    blk.header.merkleRoot = ComputeMerkleRoot(blk.vtx);
    blk.header.timestamp = ts;
    blk.header.bits = REGTEST_TARGET_BITS;
    return blk;
}

int main() {
    std::string dir = "/tmp/cdx-dbg-chain";
    std::filesystem::remove_all(dir);
    CBlockStorage storage(dir);
    CBlockchain chain(RegtestParams(), &storage);
    std::string error;
    bool ok = chain.Init(error);
    std::printf("init: %d err=%s height=%lld tip=%s\n", ok ? 1 : 0, error.c_str(),
                (long long)chain.GetHeight(), chain.GetTipHash().getHex().c_str());

    CBlock b1 = MakeRegtestBlock(chain.GetTipHash(), 1, 1001);
    std::printf("mine b1...\n");
    bool mined = MineBlockHeader(b1.header, REGTEST_TARGET_BITS, nullptr);
    std::printf("mined=%d hash=%s\n", mined ? 1 : 0, b1.GetHash().getHex().c_str());
    error.clear();
    ok = chain.AcceptBlock(b1, 1, error);
    std::printf("accept b1: %d err=%s\n", ok ? 1 : 0, error.c_str());
    return 0;
}
