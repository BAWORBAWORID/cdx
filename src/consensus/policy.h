#pragma once
#include <cstdint>
#include "config/networks.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Fee policy — BUKAN konsensus. Node boleh berbeda.
//   estimatesmartfee -> fallback DEFAULT_FEE_RATE.
// ---------------------------------------------------------------------------

// fee rate dalam base units per 1000 byte
int64_t EstimateSmartFee();
int64_t GetDefaultFeeRate();

// hitung fee dari ukuran tx (byte)
int64_t CalculateFee(size_t txSizeBytes);

} // namespace cdx
