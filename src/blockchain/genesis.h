#pragma once
#include <cstdint>
#include <string>
#include "blockchain/block.h"
#include "config/networks.h"

// Pesan genesis CDX — tunggal di satu tempat agar konsisten antara
// node (genesis.cpp) dan tool mining (bin/cdx-genesis.cpp).
inline const std::string& GetGenesisMessage() {
    static const std::string msg =
        "CDX Genesis - Codex Coin, 21,000,000 CDX, SHA-256d PoW, UTXO, P2P";
    return msg;
}

// timestamp genesis CDX (era CDX, bukan era Bitcoin)
inline constexpr uint32_t CDX_GENESIS_TIMESTAMP = 1717200000; // 2024-06-01

namespace cdx {

// ---------------------------------------------------------------------------
// Genesis block CDX — dibuat khusus untuk CDX, BUKAN Bitcoin genesis.
// Setiap network (mainnet/testnet/regtest) punya genesis sendiri.
// Node MENOLAK chain dengan genesis hash yang salah.
// ---------------------------------------------------------------------------

// bangun genesis block sesuai params (belum di-mine)
CBlock CreateGenesisBlock(uint32_t bits, int64_t rewardBase, uint32_t timestamp,
                          const std::string& message, uint32_t nonce);

// genesis untuk network tertentu; genesisHashHex harus diisi setelah mining
// (lihat scripts/genesis.cpp — tool cdx-genesis)
CBlock GetGenesisBlock(const ChainParams& params);

// hash genesis yang diharapkan; melempar bila belum diset
uint256 GetGenesisHash(const ChainParams& params);

} // namespace cdx
