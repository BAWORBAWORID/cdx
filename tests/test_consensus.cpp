#include "testfw.h"
#include "consensus/rewards.h"
#include "consensus/difficulty.h"
#include "consensus/chainwork.h"
#include "consensus/validation.h"
#include "script/interpreter.h"
#include "wallet/keypair.h"
#include "wallet/address.h"
#include "transaction/serializer.h"
#include <cstring>

using namespace cdx;

TEST(block_subsidy_initial) {
    CHECK(GetBlockSubsidy(0) == 50 * COIN);
    CHECK(GetBlockSubsidy(1) == 50 * COIN);
    CHECK(GetBlockSubsidy(HALVING_INTERVAL - 1) == 50 * COIN);
}

TEST(block_subsidy_halving) {
    CHECK(GetBlockSubsidy(HALVING_INTERVAL) == 25 * COIN);
    CHECK(GetBlockSubsidy(HALVING_INTERVAL * 2) == 12 * COIN + COIN / 2);
    // setelah 64 halving -> 0
    CHECK(GetBlockSubsidy(HALVING_INTERVAL * 64) == 0);
}

TEST(max_supply_21m) {
    // total supply = 2 * initial * interval = 21,000,000 CDX
    // (integer shift dapat menyebabkan defisit kecil dari truncation,
    //  tetapi TIDAK PERNAH melebihi 21,000,000 CDX)
    int64_t total = 0;
    int64_t h = 0;
    while (GetBlockSubsidy(h) > 0) {
        total += GetBlockSubsidy(h);
        ++h;
    }
    CHECK(total <= MAX_SUPPLY_BASE);
    CHECK(total >= MAX_SUPPLY_BASE - 1'000'000'000); // defisit < 10 CDX
    // nominal: 2 * 50 CDX * 210000 = 21,000,000 CDX
    CHECK(2 * INITIAL_BLOCK_REWARD * HALVING_INTERVAL == MAX_SUPPLY_BASE);
}

TEST(cumulative_supply) {
    CHECK(GetCumulativeSupplyAt(0) == 0);
    CHECK(GetCumulativeSupplyAt(1) == 50 * COIN);
    CHECK(GetCumulativeSupplyAt(HALVING_INTERVAL) == 50 * COIN * HALVING_INTERVAL);
}

TEST(coinbase_value_valid) {
    CHECK(IsCoinbaseValueValid(50 * COIN, 50 * COIN, 0));
    CHECK(IsCoinbaseValueValid(50 * COIN + 1000, 50 * COIN, 1000));
    CHECK(!IsCoinbaseValueValid(50 * COIN + 1001, 50 * COIN, 1000));
}

TEST(difficulty_same_interval) {
    const auto& p = MainnetParams();
    // dalam interval yang sama -> bits tidak berubah
    uint32_t bits = GetNextWorkRequired(1000, 100, 0x1d00ffffu, 1000, p);
    CHECK(bits == 0x1d00ffffu);
}

TEST(difficulty_adjustment) {
    const auto& p = MainnetParams();
    // interval baru, block LEBIH CEPAT dari target (actualTime < expectedTime)
    // -> difficulty naik (target turun)
    int64_t lastTime = 1000 + p.targetBlockTime * p.difficultyInterval / 2; // 2x cepat
    int64_t firstTime = 1000;
    uint32_t bits = GetNextWorkRequired(lastTime, p.difficultyInterval - 1,
                                        0x1d00ffffu, firstTime, p);
    uint256 target = TargetFromBits(bits);
    uint256 base = TargetFromBits(0x1d00ffffu);
    CHECK(target < base); // difficulty naik (target turun)
    // block LEBIH LAMBAT dari target (actualTime > expectedTime)
    // -> difficulty turun (target naik). Gunakan bits awal yang lebih sulit
    // (0x1c00ffff) agar hasilnya tidak ter-clamp ke max target.
    int64_t slowTime = 1000 + p.targetBlockTime * p.difficultyInterval * 2; // 2x lambat
    uint32_t hardBits = 0x1c00ffffu;
    uint256 hardTarget = TargetFromBits(hardBits);
    uint32_t bits2 = GetNextWorkRequired(slowTime, p.difficultyInterval - 1,
                                         hardBits, firstTime, p);
    uint256 target2 = TargetFromBits(bits2);
    CHECK(target2 > hardTarget); // difficulty turun (target naik)
    CHECK(target2 <= base);      // tidak pernah melewati max target
}

TEST(difficulty_max_adjustment) {
    const auto& p = MainnetParams();
    // sangat lambat -> dibatasi 4x
    int64_t lastTime = 1000 + p.targetBlockTime * p.difficultyInterval * 100;
    int64_t firstTime = 1000;
    uint32_t bits = GetNextWorkRequired(lastTime, p.difficultyInterval - 1,
                                        0x1d00ffffu, firstTime, p);
    uint256 target = TargetFromBits(bits);
    uint256 base = TargetFromBits(0x1d00ffffu);
    // max 4x: base/4 <= target
    uint256 quarter = base.div64(4);
    CHECK(target >= quarter);
}

TEST(chainwork_monotonic) {
    // difficulty naik (target turun) -> work per block naik
    uint256 w1 = GetBlockWork(0x1d00ffffu);
    uint256 w2 = GetBlockWork(0x1d00fffeu);
    CHECK(w2 > w1);
    // accumulated
    uint256 acc = w1 + w2;
    CHECK(acc > w1 && acc > w2);
}

TEST(regtest_no_retarget) {
    const auto& p = RegtestParams();
    CHECK(p.powNoRetarget);
    uint32_t bits = GetNextWorkRequired(9999999, 5000, REGTEST_TARGET_BITS, 0, p);
    CHECK(bits == REGTEST_TARGET_BITS);
}

TEST(address_validation) {
    // mainnet prefix
    CKeyPair kp = CKeyPair::Generate(0x1E);
    CHECK(kp.address.size() > 20);
    CHECK(IsValidAddress(kp.address));
    uint8_t v, h[20];
    CHECK(DecodeAddress(kp.address, v, h));
    CHECK(v == 0x1E);
    CHECK(std::memcmp(h, kp.hash160, 20) == 0);
    // invalid
    CHECK(!IsValidAddress("notanaddress"));
    CHECK(!IsValidAddress(""));
}
