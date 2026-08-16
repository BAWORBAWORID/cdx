#include <cstdio>
#include <chrono>
#include "crypto/hash.h"
#include "transaction/serializer.h"
#include "blockchain/block.h"
using namespace cdx;
int main() {
    CBlockHeader h;
    auto ser = SerializeBlockHeader(h);
    uint8_t hdr[80];
    std::memcpy(hdr, ser.data(), 80);
    auto t0 = std::chrono::steady_clock::now();
    uint64_t n = 0;
    while (n < 2000000) {
        SHA256d(hdr, 80);
        ++n;
    }
    auto t1 = std::chrono::steady_clock::now();
    double secs = std::chrono::duration<double>(t1 - t0).count();
    std::printf("hashrate: %.0f MH/s\n", n / secs / 1e6);
    return 0;
}
