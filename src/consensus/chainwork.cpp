#include "consensus/chainwork.h"
#include "consensus/difficulty.h"

namespace cdx {

uint256 GetBlockWork(const uint256& target) {
    return uint256::chainWorkOfTarget(target);
}

uint256 GetBlockWork(uint32_t bits) {
    return GetBlockWork(TargetFromBits(bits));
}

} // namespace cdx
