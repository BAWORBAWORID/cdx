#pragma once
#include <cstdint>
#include "config/networks.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Konstanta konsensus CDX (lihat config/networks.h untuk nilai).
// ---------------------------------------------------------------------------

inline constexpr int64_t MAX_BLOCK_WEIGHT = 4000000; // 4 MWU (1 MB skala lama)
inline constexpr size_t  MAX_TX_SIZE = 100000;
inline constexpr size_t  MAX_TX_COUNT_PER_BLOCK = 10000;
inline constexpr int64_t MIN_TX_FEE = 0;
inline constexpr int64_t MAX_MONEY = MAX_SUPPLY_BASE;

// waktu validasi block
bool IsBlockTimeValid(int64_t timestamp, int64_t medianTimePast, const ChainParams& params);

// height maksimum yang mungkin (semua subsidy habis)
int64_t GetMaxHeightWithSubsidy();

} // namespace cdx
