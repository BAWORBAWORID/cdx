#pragma once
#include <cstdint>
#include <map>
#include <set>
#include <vector>
#include <string>
#include "transaction/transaction.h"
#include "utxo/utxo-set.h"
#include "crypto/uint256.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Mempool — transaksi valid & belum dikonfirmasi.
// Setiap node punya mempool sendiri.
// ---------------------------------------------------------------------------
struct CTxMemPoolEntry {
    CTransaction tx;
    int64_t fee = 0;
    int64_t time = 0;
    size_t sizeBytes = 0;
    int64_t height = 0; // height saat masuk
};

class CTxMemPool {
public:
    std::map<uint256, CTxMemPoolEntry> mapTx;          // txid -> entry
    std::map<COutPoint, uint256> mapPrevOut;           // spent outpoint -> txid

    // tambah tx ke mempool; false bila double spend / duplikat
    bool AddUnchecked(const CTransaction& tx, int64_t fee, int64_t height, int64_t now);

    // cek tx valid terhadap mempool (double spend + sig) dengan view
    bool CheckTx(const CTransaction& tx, const CCoinsView& view, int64_t height,
                 int64_t& fee, std::string& error) const;

    bool Exists(const uint256& txid) const { return mapTx.count(txid) > 0; }
    bool HaveOutpoint(const COutPoint& out) const { return mapPrevOut.count(out) > 0; }

    void RemoveTx(const uint256& txid);
    void RemoveConflicts(const CTransaction& tx);

    void Clear() { mapTx.clear(); mapPrevOut.clear(); }
    size_t Size() const { return mapTx.size(); }

    // dapatkan tx untuk relay (urutan insertion deterministic)
    std::vector<const CTransaction*> GetTxs() const;

    int64_t GetTotalFees() const;

    // hapus tx yang inputnya sudah tidak valid (setelah block diterapkan)
    void RemoveSpent(const CCoinsView& view, int64_t height, std::vector<uint256>& removed);

    std::vector<uint256> GetTxids() const;
};

} // namespace cdx
