#pragma once
#include <cstdint>
#include "transaction/transaction.h"

namespace cdx {

// policy: mempool tidak menerima tx di bawah fee rate minimum
bool IsBelowMinFee(const CTransaction& tx, int64_t fee);

} // namespace cdx
