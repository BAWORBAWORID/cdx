#include "consensus/policy.h"

namespace cdx {

int64_t EstimateSmartFee() {
    // initial: fallback default fee rate
    return DEFAULT_FEE_RATE;
}

int64_t GetDefaultFeeRate() {
    return DEFAULT_FEE_RATE;
}

int64_t CalculateFee(size_t txSizeBytes) {
    int64_t fee = (int64_t)((uint64_t)txSizeBytes * (uint64_t)EstimateSmartFee() / 1000);
    if (fee < 100) fee = 100;
    return fee;
}

} // namespace cdx
