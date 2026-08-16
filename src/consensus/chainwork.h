#pragma once
#include <cstdint>
#include "crypto/uint256.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Chain work — accumulated proof-of-work.
// work(block) = 2^256 / (target + 1)
// Chain terpilih = chain dengan accumulated work tertinggi.
// ---------------------------------------------------------------------------

uint256 GetBlockWork(uint32_t bits);
uint256 GetBlockWork(const uint256& target);

} // namespace cdx
