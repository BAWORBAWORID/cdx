#include "mining/pow.h"
#include "consensus/difficulty.h"
#include "transaction/serializer.h"
#include "crypto/hash.h"
#include "crypto/encoding.h"
#include <chrono>

namespace cdx {

bool CheckPoW(const uint256& hash, uint32_t bits) {
    return CheckProofOfWork(hash, bits);
}

bool MineBlockHeader(CBlockHeader& header, uint32_t bits,
                     const std::function<bool()>& stopFlag) {
    uint256 target = TargetFromBits(bits);
    if (target.isZero()) return false;
    header.bits = bits;

    auto headerSer = SerializeBlockHeader(header);
    uint8_t hdr[80];
    std::memcpy(hdr, headerSer.data(), 80);

    uint32_t nonce = 0;
    // rolling loop nonce 0..0xffffffff
    while (true) {
        if (stopFlag && stopFlag()) return false;
        // update nonce di byte 76..79
        uint8_t b[4];
        WriteU32LE(b, nonce);
        hdr[76] = b[0]; hdr[77] = b[1]; hdr[78] = b[2]; hdr[79] = b[3];
        uint256 hash = SHA256d(hdr, 80);
        if (hash <= target) {
            header.nonce = nonce;
            return true;
        }
        ++nonce;
        if (nonce == 0) break; // nonce exhausted
    }
    return false;
}

} // namespace cdx
