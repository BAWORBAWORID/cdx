#include "mempool/policy.h"
#include "consensus/policy.h"
#include "transaction/serializer.h"

namespace cdx {

bool IsBelowMinFee(const CTransaction& tx, int64_t fee) {
    size_t size = SerializeTransaction(tx).size();
    int64_t minFee = CalculateFee(size);
    return fee < minFee;
}

} // namespace cdx
