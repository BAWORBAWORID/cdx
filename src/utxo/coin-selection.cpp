#include "utxo/coin-selection.h"
#include <algorithm>

namespace cdx {

CoinSelectionResult SelectCoinsGreedy(const CCoinsView& view, int64_t amountNeeded) {
    CoinSelectionResult r;
    std::vector<std::pair<COutPoint, CUTXO>> coins;
    for (const auto& kv : view.utxo)
        coins.push_back({kv.first, kv.second});
    std::sort(coins.begin(), coins.end(), [](const auto& a, const auto& b) {
        return a.second.value < b.second.value;
    });
    int64_t total = 0;
    for (const auto& c : coins) {
        r.inputs.push_back(c.first);
        r.totalValue += c.second.value;
        if (r.totalValue >= amountNeeded) {
            r.sufficient = true;
            break;
        }
    }
    return r;
}

} // namespace cdx
