#include <cstdio>
#include <cstring>
#include "crypto/hash.h"
#include "crypto/encoding.h"
using namespace cdx;

int main() {
    uint8_t out[20];
    RIPEMD160((const uint8_t*)"", 0, out);
    std::printf("empty: %s (expected 9c1185a5c5e9fc54612808977ee8f548b2258d31)\n", toHex(out, 20).c_str());
    RIPEMD160((const uint8_t*)"abc", 3, out);
    std::printf("abc:   %s (expected 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc)\n", toHex(out, 20).c_str());
    return 0;
}
