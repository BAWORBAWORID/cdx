#pragma once
#include <cstdint>
#include "config/networks.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Block reward — ditentukan murni dari block height (deterministic).
// getBlockSubsidy(height):
//   subsidy = INITIAL_BLOCK_REWARD >> (height / HALVING_INTERVAL)
//   subsidy = 0 ketika height >= 64 * HALVING_INTERVAL
// Total: 50 + 25 + ... = 2 * 50 * 210000 = 21.000.000 CDX.
// ---------------------------------------------------------------------------

int64_t GetBlockSubsidy(int64_t height);

// cek apakah block reward coinbase melebihi subsidy + fees
bool IsCoinbaseValueValid(int64_t coinbaseValue, int64_t subsidy, int64_t fees);

// total supply yang valid pada height tertentu (base units)
int64_t GetCumulativeSupplyAt(int64_t height);

} // namespace cdx
