#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace cdx {

// ---------------------------------------------------------------------------
// Chain parameters — CDX memiliki parameter rantai sendiri (bukan Bitcoin).
// ---------------------------------------------------------------------------
struct ChainParams {
    std::string name;               // "mainnet" | "testnet" | "regtest"
    std::string genesisHashHex;     // CDX_<NET>_GENESIS_HASH (display order)
    uint32_t genesisNonce;          // nonce genesis (agar node tidak perlu re-mine)
    uint32_t networkMagic;          // CDX_<NET>_MAGIC (4 bytes, little-endian)
    uint16_t defaultPort;           // port P2P
    uint16_t rpcPort;               // port RPC (localhost)
    uint8_t addressVersion;         // version byte Base58Check untuk alamat P2PKH
    uint8_t privkeyVersion;         // version byte WIF
    std::string bech32Hrp;          // human-readable part (dokumentasi; primary = Base58Check)

    int64_t initialBlockReward;     // base units (1 CDX = 100_000_000 base)
    int64_t halvingInterval;        // jumlah block antar halving
    int64_t targetBlockTime;        // detik target antar block
    int64_t difficultyInterval;     // block per penyesuaian difficulty
    int64_t maxAdjustment;          // faktor max penyesuaian (4 = 4x)
    int64_t coinbaseMaturity;       // block sebelum coinbase dapat dibelanjakan
    int64_t maxSupplyBase;          // 21_000_000 * 100_000_000
    bool   powNoRetarget;           // regtest: difficulty tetap
    bool   allowMinDifficulty;      // testnet/regtest: block orphan boleh min difficulty
    uint32_t minDifficultyBits;     // target minimum (0x1d00ffff standar; regtest lebih mudah)
    int64_t maxBlockSize;           // bytes
    int64_t defaultFeeRate;         // base units / byte (fallback estimatesmartfee)
    std::vector<std::string> seedNodes;
    std::string peerRegistryUri;    // MongoDB URI peer registry (opsional, non-konsensus)
};

// Network magic values — identitas CDX sendiri.
inline constexpr uint32_t CDX_MAINNET_MAGIC  = 0xCDA1CD01u; // 'CDX' + 01
inline constexpr uint32_t CDX_TESTNET_MAGIC  = 0xCDA1CD02u; // 'CDX' + 02
inline constexpr uint32_t CDX_REGTEST_MAGIC  = 0xCDA1CDFFu; // 'CDX' + FF

// Port P2P CDX sendiri (bukan 8333 milik Bitcoin).
inline constexpr uint16_t CDX_MAINNET_PORT = 18333 + 1000; // 19333 — CDX
inline constexpr uint16_t CDX_TESTNET_PORT = 19334;
inline constexpr uint16_t CDX_REGTEST_PORT = 19444;
inline constexpr uint16_t CDX_MAINNET_RPC  = 19343;
inline constexpr uint16_t CDX_TESTNET_RPC  = 19344;
inline constexpr uint16_t CDX_REGTEST_RPC  = 19445;

// Base unit: 1 CDX = 100_000_000 base units (8 desimal).
inline constexpr int64_t COIN = 100'000'000;
// Hard maximum supply: 21_000_000 CDX.
inline constexpr int64_t MAX_SUPPLY_BASE = 21'000'000LL * COIN;

// Konstanta waktu konsensus.
inline constexpr int64_t TARGET_BLOCK_TIME_MAIN = 600;    // 10 menit
inline constexpr int64_t DIFFICULTY_INTERVAL     = 2016;  // 2 minggu pada 10 menit/block
inline constexpr int64_t MAX_ADJUSTMENT          = 4;

// Halving: 50 CDX per block, halving tiap 210.000 block => total 21.000.000 CDX.
inline constexpr int64_t INITIAL_BLOCK_REWARD = 50 * COIN;
inline constexpr int64_t HALVING_INTERVAL     = 210'000;

inline constexpr int64_t COINBASE_MATURITY = 120;

inline constexpr int64_t MAX_BLOCK_SIZE = 1'000'000; // 1 MB
inline constexpr int64_t DEFAULT_FEE_RATE = 1000;    // 0.00001 CDX / KB

// Target bits default (0x1d00ffff setara Bitcoin genesis).
inline constexpr uint32_t DEFAULT_TARGET_BITS = 0x1d00ffffu;
// Target regtest — jauh lebih mudah agar mining instan di development.
inline constexpr uint32_t REGTEST_TARGET_BITS = 0x207fffffu;

const ChainParams& MainnetParams();
const ChainParams& TestnetParams();
const ChainParams& RegtestParams();
const ChainParams& GetParams(const std::string& network);

} // namespace cdx
