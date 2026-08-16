#pragma once
#include <cstdint>
#include <map>
#include <vector>
#include "crypto/uint256.h"
#include "transaction/transaction.h"
#include "config/networks.h"

namespace cdx {

// ---------------------------------------------------------------------------
// UTXO — Unspent Transaction Output.
// UTXO: txid + vout + value + scriptPubKey + height + coinbase flag.
// Balance = sum(spendable UTXOs). Tidak ada balance centralized.
// ---------------------------------------------------------------------------
struct CUTXO {
    int64_t value = 0;            // base units
    std::vector<uint8_t> scriptPubKey;
    int64_t height = 0;           // block height tempat output dibuat
    bool isCoinbase = false;      // coinbase UTXO (maturity 120)

    bool IsSpendable(int64_t currentHeight) const {
        if (isCoinbase && currentHeight - height < COINBASE_MATURITY) return false;
        return true;
    }
};

// Map: OutPoint -> UTXO. Urutan deterministic (map).
class CCoinsView {
public:
    std::map<COutPoint, CUTXO> utxo;

    bool GetCoin(const COutPoint& out, CUTXO& coin) const {
        auto it = utxo.find(out);
        if (it == utxo.end()) return false;
        coin = it->second;
        return true;
    }
    bool HaveCoin(const COutPoint& out) const { return utxo.count(out) > 0; }
    void AddCoin(const COutPoint& out, const CUTXO& coin) { utxo[out] = coin; }
    bool SpendCoin(const COutPoint& out) { return utxo.erase(out) > 0; }
    size_t Size() const { return utxo.size(); }

    // total nilai UTXO yang dimiliki alamat tertentu (hash160)
    int64_t GetAddressBalance(const uint8_t hash160[20], int64_t currentHeight,
                              int64_t& confirmed, int64_t& unconfirmed,
                              int64_t& immature) const;

    // total semua UTXO (untuk audit supply)
    int64_t TotalValue() const {
        int64_t total = 0;
        for (const auto& kv : utxo) total += kv.second.value;
        return total;
    }
};

// helper: hash OutPoint untuk map (pakai map biasa, sudah cukup)
} // namespace cdx
