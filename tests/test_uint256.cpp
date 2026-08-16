#include "testfw.h"
#include "crypto/uint256.h"

using namespace cdx;

TEST(uint256_add_sub) {
    uint256 a = uint256(5);
    uint256 b = uint256(7);
    CHECK((a + b).w[0] == 12);
    CHECK((b - a).w[0] == 2);
    // carry
    uint256 big;
    big.w[0] = ~0ull;
    uint256 r = big + uint256(1);
    CHECK(r.w[0] == 0);
    CHECK(r.w[1] == 1);
}

TEST(uint256_shift) {
    uint256 a = uint256(1);
    CHECK((a << 64).w[1] == 1);
    CHECK((a << 255).w[3] == (1ull << 63));
    uint256 b = a << 100;
    CHECK((b >> 100).w[0] == 1);
}

TEST(uint256_compare) {
    uint256 a = uint256::fromHex("00000000000000000000000000000000000000000000000000000000000000ff");
    uint256 b = uint256::fromHex("0000000000000000000000000000000000000000000000000000000000000100");
    CHECK(a < b);
    CHECK(b > a);
    CHECK(a == a);
}

TEST(uint256_div) {
    // 10 / 3 = 3
    uint256 a = uint256(10);
    uint256 d = uint256(3);
    CHECK(a.div(d).w[0] == 3);
    // big: (1<<128) / (1<<64) = 1<<64
    uint256 big = uint256(1) << 128;
    uint256 small = uint256(1) << 64;
    CHECK(big.div(small).w[1] == 1);
    CHECK(big.div(small).w[0] == 0);
}

TEST(uint256_mul_div64) {
    uint256 a = uint256(1000);
    CHECK(a.mul64(3).w[0] == 3000);
    uint64_t rem = 999;
    uint256 q = a.div64(7, &rem);
    CHECK(q.w[0] == 142);
    CHECK(rem == 6);
}
