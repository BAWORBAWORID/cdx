#pragma once
#include <cstdint>
#include "crypto/uint256.h"
#include "config/networks.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Difficulty — node menghitung expected target sendiri.
// Miner TIDAK menentukan difficulty.
//
// Format bits: compact (0x1d00ffff style).
//   target = SetCompact(bits)
//   difficulty = maxTarget / target
//
// Penyesuaian tiap DIFFICULTY_INTERVAL block:
//   newTarget = prevTarget * actualTime / expectedTime
//   dibatasi MAX_ADJUSTMENT (4x).
// ---------------------------------------------------------------------------

uint256 GetMaxTarget(); // target minimum difficulty (0x1d00ffff)

uint32_t GetNextWorkRequired(int64_t lastBlockTime, int64_t lastBlockHeight,
                             uint32_t lastBits,
                             int64_t firstBlockTimeOfInterval,
                             const ChainParams& params);

// difficulty (double) dari bits — hanya untuk display, bukan consensus
double GetDifficultyFromBits(uint32_t bits);

// target dari bits
inline uint256 TargetFromBits(uint32_t bits) { return uint256::setCompact(bits); }

// cek PoW: hash <= target
bool CheckProofOfWork(const uint256& hash, uint32_t bits);

} // namespace cdx
