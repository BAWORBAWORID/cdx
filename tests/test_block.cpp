#include "testfw.h"
#include "blockchain/block.h"
#include "blockchain/merkle.h"
#include "blockchain/genesis.h"
#include "consensus/difficulty.h"
#include "mining/pow.h"
#include "transaction/serializer.h"
#include "crypto/encoding.h"

using namespace cdx;

TEST(block_hash_deterministic) {
    CBlockHeader hdr;
    hdr.version = 1;
    hdr.prevBlockHash = uint256(0xabc);
    hdr.merkleRoot = uint256(0xdef);
    hdr.timestamp = 1000;
    hdr.bits = 0x1d00ffff;
    hdr.nonce = 7;
    uint256 h7 = hdr.GetHash();
    CHECK(h7 == hdr.GetHash()); // deterministik
    hdr.nonce = 8;
    uint256 h8 = hdr.GetHash();
    CHECK(h7 != h8);
}

TEST(pow_check) {
    // regtest bits 0x207fffff: target = 0x7fffff << 232
    // hash dengan bit tertinggi 0 dan <= target harus lolos
    CBlockHeader hdr;
    hdr.bits = REGTEST_TARGET_BITS;
    uint256 target = TargetFromBits(hdr.bits);
    CHECK(!target.isZero());
    // hash nol pasti lolos
    CHECK(CheckProofOfWork(uint256(), hdr.bits));
    // hash sama dengan target lolos
    CHECK(CheckProofOfWork(target, hdr.bits));
    // hash > target gagal
    CHECK(!CheckProofOfWork(target + uint256(1), hdr.bits));
    // mining regtest harus menemukan nonce
    hdr.nonce = 0;
    CHECK(MineBlockHeader(hdr, REGTEST_TARGET_BITS, nullptr));
    CHECK(CheckProofOfWork(hdr.GetHash(), hdr.bits));
    // target sangat kecil -> hampir pasti gagal
    CHECK(!CheckProofOfWork(uint256::fromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), 0x1d00ffffu));
}

TEST(genesis_block_structure) {
    CBlock g = CreateGenesisBlock(0x1d00ffffu, INITIAL_BLOCK_REWARD, 1717200000,
                                  "CDX genesis test", 0);
    CHECK(g.vtx.size() == 1);
    CHECK(g.vtx[0].IsCoinBase());
    CHECK(g.vtx[0].vout[0].value == INITIAL_BLOCK_REWARD);
    CHECK(g.header.prevBlockHash.isZero());
    CHECK(g.CheckMerkleRoot());
    // serialization roundtrip
    auto ser = SerializeBlock(g);
    CBlock g2;
    CHECK(DeserializeBlock(ser.data(), ser.size(), g2));
    CHECK(g2.GetHash() == g.GetHash());
    CHECK(g2.vtx.size() == 1);
    CHECK(g2.vtx[0].vout[0].value == INITIAL_BLOCK_REWARD);
}

TEST(genesis_merkle_matches_header) {
    CBlock g = CreateGenesisBlock(0x1d00ffffu, INITIAL_BLOCK_REWARD, 1717200000,
                                  "merkle check", 1);
    CHECK(g.header.merkleRoot == ComputeMerkleRoot(g.vtx));
}
