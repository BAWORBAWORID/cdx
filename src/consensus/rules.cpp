#include "consensus/rules.h"

namespace cdx {

bool IsBlockTimeValid(int64_t timestamp, int64_t medianTimePast, const ChainParams& params) {
    (void)params;
    // block tidak boleh lebih dari 2 jam di masa depan
    int64_t now = (int64_t)time(nullptr);
    if (timestamp > now + 2 * 3600) return false;
    return true;
}

int64_t GetMaxHeightWithSubsidy() {
    return 64 * HALVING_INTERVAL;
}

} // namespace cdx
