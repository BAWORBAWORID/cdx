#include <cstdio>
#include "wallet/keystore.h"
#include "wallet/wallet.h"
#include "consensus/difficulty.h"
#include "blockchain/block.h"
#include "transaction/serializer.h"
#include "crypto/hash.h"
#include "crypto/encoding.h"
using namespace cdx;

int main() {
    // test 1: keystore unlock
    CKeystore ks;
    bool ok = ks.Unlock("testpassword");
    std::printf("keystore unlock: %d\n", ok ? 1 : 0);
    if (!ok) return 1;

    // test 2: PoW regtest
    CBlockHeader hdr;
    hdr.bits = REGTEST_TARGET_BITS;
    uint256 target = TargetFromBits(hdr.bits);
    std::printf("regtest target bits=0x%08x\n  target=%s\n", REGTEST_TARGET_BITS, target.getHex().c_str());
    for (int i = 0; i < 5; ++i) {
        hdr.nonce = i;
        uint256 h = hdr.GetHash();
        std::printf("  nonce=%d hash=%s\n    <= target? %d\n", i, h.getHex().c_str(),
                    CheckProofOfWork(h, hdr.bits) ? 1 : 0);
    }
    // cek bits roundtrip
    uint256 t1 = TargetFromBits(REGTEST_TARGET_BITS);
    uint32_t back = t1.getCompact();
    std::printf("compact roundtrip: 0x%08x -> 0x%08x\n", REGTEST_TARGET_BITS, back);
    return 0;
}
