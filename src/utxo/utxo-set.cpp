#include "utxo/utxo-set.h"
#include "script/interpreter.h"
#include <cstring>

namespace cdx {

int64_t CCoinsView::GetAddressBalance(const uint8_t hash160[20], int64_t currentHeight,
                                      int64_t& confirmed, int64_t& unconfirmed,
                                      int64_t& immature) const {
    confirmed = 0;
    unconfirmed = 0;
    immature = 0;
    for (const auto& kv : utxo) {
        uint8_t h[20];
        if (!ExtractP2PKHHash(kv.second.scriptPubKey, h)) continue;
        if (std::memcmp(h, hash160, 20) != 0) continue;
        if (kv.second.isCoinbase && currentHeight - kv.second.height < COINBASE_MATURITY) {
            immature += kv.second.value;
        } else if (kv.second.height > currentHeight) {
            unconfirmed += kv.second.value;
        } else {
            confirmed += kv.second.value;
        }
    }
    return confirmed + unconfirmed + immature;
}

} // namespace cdx
