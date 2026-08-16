#include <cstdio>
#include "crypto/uint256.h"
using namespace cdx;
int main() {
    uint256 v = uint256::fromHex("0000000000000000000000000000000000000000000000000000000000000001");
    std::printf("w0=%016llx w1=%016llx w2=%016llx w3=%016llx\n",
                (unsigned long long)v.w[0], (unsigned long long)v.w[1],
                (unsigned long long)v.w[2], (unsigned long long)v.w[3]);
    std::printf("hex=%s\n", v.getHex().c_str());
    uint256 t = uint256::setCompact(0x1d00ffffu);
    std::printf("target hex=%s\n", t.getHex().c_str());
    std::printf("compact back=%08x\n", t.getCompact());
    return 0;
}
