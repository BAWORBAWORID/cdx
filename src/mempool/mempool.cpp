#include "mempool/mempool.h"
#include "consensus/validation.h"
#include "transaction/serializer.h"

namespace cdx {

bool CTxMemPool::AddUnchecked(const CTransaction& tx, int64_t fee, int64_t height, int64_t now) {
    uint256 txid = GetTxID(tx);
    if (mapTx.count(txid)) return false;
    CTxMemPoolEntry e;
    e.tx = tx;
    e.fee = fee;
    e.time = now;
    e.height = height;
    e.sizeBytes = SerializeTransaction(tx).size();
    mapTx[txid] = std::move(e);
    for (const auto& in : tx.vin)
        mapPrevOut[in.prevout] = txid;
    return true;
}

bool CTxMemPool::CheckTx(const CTransaction& tx, const CCoinsView& view, int64_t height,
                         int64_t& fee, std::string& error) const {
    // tidak boleh coinbase
    if (tx.IsCoinBase()) {
        error = "coinbase cannot enter mempool";
        return false;
    }
    if (!CheckTransaction(tx, error)) return false;
    // double spend terhadap mempool
    for (const auto& in : tx.vin) {
        if (mapPrevOut.count(in.prevout)) {
            error = "double spend (already in mempool)";
            return false;
        }
    }
    // conflict terhadap UTXO view
    if (!CheckTxInputs(tx, view, height, fee, error)) return false;
    // fee minimum (policy)
    if (fee < 100) {
        error = "fee below minimum";
        return false;
    }
    return true;
}

void CTxMemPool::RemoveTx(const uint256& txid) {
    auto it = mapTx.find(txid);
    if (it == mapTx.end()) return;
    for (const auto& in : it->second.tx.vin) {
        auto pit = mapPrevOut.find(in.prevout);
        if (pit != mapPrevOut.end() && pit->second == txid) mapPrevOut.erase(pit);
    }
    mapTx.erase(it);
}

void CTxMemPool::RemoveConflicts(const CTransaction& tx) {
    for (const auto& in : tx.vin) {
        auto it = mapPrevOut.find(in.prevout);
        if (it != mapPrevOut.end()) {
            RemoveTx(it->second);
        }
    }
}

std::vector<const CTransaction*> CTxMemPool::GetTxs() const {
    std::vector<const CTransaction*> out;
    out.reserve(mapTx.size());
    for (const auto& kv : mapTx) out.push_back(&kv.second.tx);
    return out;
}

int64_t CTxMemPool::GetTotalFees() const {
    int64_t total = 0;
    for (const auto& kv : mapTx) total += kv.second.fee;
    return total;
}

void CTxMemPool::RemoveSpent(const CCoinsView& view, int64_t height, std::vector<uint256>& removed) {
    std::vector<uint256> toRemove;
    for (const auto& kv : mapTx) {
        const auto& tx = kv.second.tx;
        bool invalid = false;
        for (const auto& in : tx.vin) {
            CUTXO coin;
            if (!view.GetCoin(in.prevout, coin)) { invalid = true; break; }
            if (!coin.IsSpendable(height)) { invalid = true; break; }
        }
        if (invalid) toRemove.push_back(kv.first);
    }
    for (const auto& id : toRemove) {
        RemoveTx(id);
        removed.push_back(id);
    }
}

std::vector<uint256> CTxMemPool::GetTxids() const {
    std::vector<uint256> out;
    out.reserve(mapTx.size());
    for (const auto& kv : mapTx) out.push_back(kv.first);
    return out;
}

} // namespace cdx
