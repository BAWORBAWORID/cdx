#include "consensus/rewards.h"

namespace cdx {

int64_t GetBlockSubsidy(int64_t height) {
    int64_t halvings = height / HALVING_INTERVAL;
    if (halvings >= 64) return 0;
    return INITIAL_BLOCK_REWARD >> halvings;
}

bool IsCoinbaseValueValid(int64_t coinbaseValue, int64_t subsidy, int64_t fees) {
    return coinbaseValue <= subsidy + fees;
}

int64_t GetCumulativeSupplyAt(int64_t height) {
    // jumlah block penuh hingga height (eksklusif)
    int64_t total = 0;
    int64_t h = 0;
    while (h < height) {
        int64_t subsidy = GetBlockSubsidy(h);
        if (subsidy == 0) break;
        // berapa lama subsidy ini berlaku
        int64_t intervalEnd = ((h / HALVING_INTERVAL) + 1) * HALVING_INTERVAL;
        int64_t end = intervalEnd < height ? intervalEnd : height;
        total += subsidy * (end - h);
        h = end;
    }
    return total;
}

} // namespace cdx
