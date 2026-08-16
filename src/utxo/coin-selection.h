#pragma once
#include <cstdint>
#include <vector>
#include "transaction/transaction.h"
#include "utxo/utxo-set.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Coin selection — memilih UTXO untuk membayar amount.
// Strategi: smallest sufficient (ascending value).
// ---------------------------------------------------------------------------
struct CoinSelectionResult {
    std::vector<COutPoint> inputs;
    int64_t totalValue = 0;
    bool sufficient = false;
};

CoinSelectionResult SelectCoinsGreedy(const CCoinsView& view, int64_t amountNeeded);

} // namespace cdx
