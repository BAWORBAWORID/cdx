#include "config/networks.h"

namespace cdx {

static const ChainParams MAINNET = {
    /* name               */ "mainnet",
    /* genesisHashHex     */ "000000003c2ec558c762a6b2ed57e3b6aef5bcec8df70defca767f4d94e01643", // di-mine via tools/mine_genesis
    /* genesisNonce       */ 983536281u,
    /* networkMagic       */ CDX_MAINNET_MAGIC,
    /* defaultPort        */ CDX_MAINNET_PORT,
    /* rpcPort            */ CDX_MAINNET_RPC,
    /* addressVersion     */ 0x1E, // CDX mainnet address prefix
    /* privkeyVersion     */ 0x9E,
    /* bech32Hrp          */ "cdx",
    /* initialBlockReward */ INITIAL_BLOCK_REWARD,
    /* halvingInterval    */ HALVING_INTERVAL,
    /* targetBlockTime    */ TARGET_BLOCK_TIME_MAIN,
    /* difficultyInterval */ DIFFICULTY_INTERVAL,
    /* maxAdjustment      */ MAX_ADJUSTMENT,
    /* coinbaseMaturity   */ COINBASE_MATURITY,
    /* maxSupplyBase      */ MAX_SUPPLY_BASE,
    /* powNoRetarget      */ false,
    /* allowMinDifficulty */ false,
    /* minDifficultyBits  */ DEFAULT_TARGET_BITS,
    /* maxBlockSize       */ MAX_BLOCK_SIZE,
    /* defaultFeeRate     */ DEFAULT_FEE_RATE,
    /* seedNodes          */ {"seed.cdx.network", "seed.cdx.mine"},
    /* peerRegistryUri    */ "mongodb+srv://admin:admin@cluster0.rijgohu.mongodb.net/?appName=Cluster0",
};

static const ChainParams TESTNET = {
    "testnet",
    "",
    0u,
    CDX_TESTNET_MAGIC,
    CDX_TESTNET_PORT,
    CDX_TESTNET_RPC,
    0x4F, // CDX testnet address prefix
    0xCF,
    "tcdx",
    INITIAL_BLOCK_REWARD,
    HALVING_INTERVAL,
    TARGET_BLOCK_TIME_MAIN,
    DIFFICULTY_INTERVAL,
    MAX_ADJUSTMENT,
    COINBASE_MATURITY,
    MAX_SUPPLY_BASE,
    false,
    true,  // allowMinDifficulty — testnet bisa naik kembali dengan mudah
    DEFAULT_TARGET_BITS,
    MAX_BLOCK_SIZE,
    DEFAULT_FEE_RATE,
    {"testnet-seed.cdx.network"},
    "mongodb+srv://admin:admin@cluster0.rijgohu.mongodb.net/?appName=Cluster0",
};

static const ChainParams REGTEST = {
    "regtest",
    "6cd19df11dc9155a19c4531cc699d8bfd082a7526c3f73a0d9061bde3c8bcdcd",
    0u,
    CDX_REGTEST_MAGIC,
    CDX_REGTEST_PORT,
    CDX_REGTEST_RPC,
    0x6F, // prefix regtest CDX
    0xEF,
    "crx",
    INITIAL_BLOCK_REWARD,
    HALVING_INTERVAL,
    TARGET_BLOCK_TIME_MAIN,
    DIFFICULTY_INTERVAL,
    MAX_ADJUSTMENT,
    COINBASE_MATURITY,
    MAX_SUPPLY_BASE,
    true,                 // powNoRetarget — difficulty tetap
    true,
    REGTEST_TARGET_BITS,  // difficulty sangat rendah untuk dev
    MAX_BLOCK_SIZE,
    DEFAULT_FEE_RATE,
    {},
    "mongodb+srv://admin:admin@cluster0.rijgohu.mongodb.net/?appName=Cluster0",
};

const ChainParams& MainnetParams() { return MAINNET; }
const ChainParams& TestnetParams() { return TESTNET; }
const ChainParams& RegtestParams() { return REGTEST; }

const ChainParams& GetParams(const std::string& network) {
    if (network == "testnet") return TestnetParams();
    if (network == "regtest") return RegtestParams();
    return MainnetParams();
}

} // namespace cdx
