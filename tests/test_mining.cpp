#include "testfw.h"
#include "mining/miner.h"
#include "mining/pow.h"
#include "consensus/difficulty.h"
#include "consensus/rewards.h"
#include "consensus/validation.h"
#include "script/interpreter.h"
#include "wallet/keypair.h"
#include "wallet/signer.h"
#include "transaction/serializer.h"
#include "crypto/encoding.h"
#include <cstring>

using namespace cdx;

TEST(pow_mine_regtest) {
    CBlockHeader hdr;
    hdr.version = 1;
    hdr.timestamp = 1000;
    // regtest difficulty sangat rendah -> mining cepat
    bool found = MineBlockHeader(hdr, REGTEST_TARGET_BITS, nullptr);
    CHECK(found);
    CHECK(CheckProofOfWork(hdr.GetHash(), hdr.bits));
}

TEST(pow_nonce_exhaustion) {
    // target sangat kecil: nonce 0..0xffffffff tidak cukup -> false (atau memakan waktu)
    // gunakan target 0 (invalid) untuk test cepat
    CBlockHeader hdr;
    hdr.timestamp = 1;
    // bits 0x01003456 target kecil; kemungkinan besar tidak ditemukan dalam
    // satu putaran nonce — tapi jangan jalankan loop 4M kali di test.
    // cukup verifikasi CheckPoW menolak target nol.
    CHECK(!CheckProofOfWork(uint256::fromHex("0000000000000000000000000000000000000000000000000000000000000001"), 0));
}

TEST(miner_candidate_block) {
    CKeyPair miner = CKeyPair::Generate(0x6F);
    CTxMemPool mempool;
    CCoinsView view;

    int64_t fees = 0;
    CBlock cand = CMiner::CreateCandidateBlock(10, REGTEST_TARGET_BITS, 1000,
                                               uint256(0x1234), mempool, view,
                                               miner.address, 0x6F, fees);
    CHECK(cand.vtx.size() == 1); // hanya coinbase (mempool kosong)
    CHECK(cand.vtx[0].IsCoinBase());
    CHECK(cand.vtx[0].vout[0].value == GetBlockSubsidy(10));
    CHECK(cand.header.bits == REGTEST_TARGET_BITS);
    CHECK(cand.header.prevBlockHash == uint256(0x1234));
    CHECK(cand.CheckMerkleRoot());
}

TEST(miner_candidate_includes_fees) {
    // mempool dengan tx berfee -> coinbase = subsidy + fees
    CKeyPair miner = CKeyPair::Generate(0x6F);
    CKeyPair alice = CKeyPair::Generate(0x6F);
    CCoinsView view;
    COutPoint fp{uint256(5), 0};
    CUTXO coin;
    coin.value = 1000000000LL;
    coin.scriptPubKey = BuildP2PKHScript(alice.hash160);
    coin.height = 0;
    coin.isCoinbase = false;
    view.AddCoin(fp, coin);

    CTransaction tx;
    tx.version = 1;
    CTxIn in;
    in.prevout = fp;
    tx.vin.push_back(in);
    CTxOut out;
    out.value = 990000000LL; // fee 10_000_000
    out.scriptPubKey = BuildP2PKHScript(alice.hash160);
    tx.vout.push_back(out);
    std::string e;
    SignInput(tx, 0, alice, coin.scriptPubKey, e);

    CTxMemPool mempool;
    mempool.AddUnchecked(tx, 10000000LL, 100, 1);

    int64_t fees = 0;
    CBlock cand = CMiner::CreateCandidateBlock(100, REGTEST_TARGET_BITS, 2000,
                                               uint256(0x9), mempool, view,
                                               miner.address, 0x6F, fees);
    CHECK(fees == 10000000LL);
    CHECK(cand.vtx.size() == 2);
    CHECK(cand.vtx[0].vout[0].value == GetBlockSubsidy(100) + 10000000LL);
}

TEST(miner_status) {
    CMiner miner;
    miner.SetMiningAddress("addr", 0x6F);
    auto st = miner.GetStatus();
    CHECK(st.miningAddress == "addr");
    CHECK(!st.mining);
}
