#include "consensus/difficulty.h"
#include "consensus/rules.h"

namespace cdx {

uint256 GetMaxTarget() {
    return uint256::setCompact(DEFAULT_TARGET_BITS);
}

bool CheckProofOfWork(const uint256& hash, uint32_t bits) {
    uint256 target = TargetFromBits(bits);
    // target nol selalu invalid
    if (target.isZero()) return false;
    return hash <= target;
}

uint32_t GetNextWorkRequired(int64_t lastBlockTime, int64_t lastBlockHeight,
                             uint32_t lastBits,
                             int64_t firstBlockTimeOfInterval,
                             const ChainParams& params) {
    if (params.powNoRetarget) return lastBits;

    bool isNewInterval = (lastBlockHeight + 1) % params.difficultyInterval == 0;
    if (!isNewInterval) return lastBits;

    // interval baru: hitung penyesuaian
    int64_t actualTime = lastBlockTime - firstBlockTimeOfInterval;
    if (actualTime < params.targetBlockTime / 4) actualTime = params.targetBlockTime / 4;
    int64_t expectedTime = params.targetBlockTime * params.difficultyInterval;
    if (actualTime > expectedTime * params.maxAdjustment) {
        actualTime = expectedTime * params.maxAdjustment;
    }

    uint256 target = TargetFromBits(lastBits);
    // newTarget = target * actualTime / expectedTime
    // gunakan BigInt (uint256) — tidak ada floating point
    uint256 newTarget = target.mul64((uint64_t)actualTime).div64((uint64_t)expectedTime);

    // jangan pernah di atas max target
    uint256 maxTarget = TargetFromBits(params.minDifficultyBits);
    if (newTarget > maxTarget) newTarget = maxTarget;

    return newTarget.getCompact();
}

double GetDifficultyFromBits(uint32_t bits) {
    uint256 target = TargetFromBits(bits);
    if (target.isZero()) return 0.0;
    // difficulty = maxTarget / target (approximate via double)
    uint256 maxTarget = GetMaxTarget();
    // hitung perbandingan sebagai double
    double t = 0.0;
    for (int i = 3; i >= 0; --i) {
        t = t * 18446744073709551616.0 + (double)target.w[i];
    }
    double m = 0.0;
    for (int i = 3; i >= 0; --i) {
        m = m * 18446744073709551616.0 + (double)maxTarget.w[i];
    }
    return m / t;
}

} // namespace cdx
