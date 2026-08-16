#include "testfw.h"
#include "blockchain/merkle.h"
#include "config/networks.h"
#include "transaction/serializer.h"
#include "crypto/hash.h"

using namespace cdx;

TEST(merkle_single) {
    CTransaction tx;
    CTxIn in;
    in.prevout.hash.clear();
    in.prevout.n = 0xffffffff;
    tx.vin.push_back(in);
    CTxOut out;
    out.value = 50 * COIN;
    tx.vout.push_back(out);
    uint256 txid = GetTxID(tx);
    uint256 root = ComputeMerkleRoot(std::vector<CTransaction>{tx});
    CHECK(root == txid); // satu tx -> root = txid
}

TEST(merkle_four) {
    std::vector<uint256> hashes;
    for (int i = 1; i <= 4; ++i) {
        hashes.push_back(uint256((uint64_t)i));
    }
    uint256 root = ComputeMerkleRoot(hashes);
    CHECK(!root.isZero());
    // deterministik
    CHECK(root == ComputeMerkleRoot(hashes));
}

TEST(merkle_odd) {
    // 3 elemen: duplikasi elemen terakhir
    std::vector<uint256> hashes;
    for (int i = 1; i <= 3; ++i) hashes.push_back(uint256((uint64_t)i));
    uint256 root = ComputeMerkleRoot(hashes);
    CHECK(!root.isZero());
    // bandingkan dengan implementasi manual (h1,h2),(h3,h3) -> (h12,h33)
    uint8_t buf[64];
    hashes[0].getBytesLE(buf);
    hashes[1].getBytesLE(buf + 32);
    uint8_t h12[32];
    SHA256d(buf, 64, h12);
    hashes[2].getBytesLE(buf);
    hashes[2].getBytesLE(buf + 32);
    uint8_t h33[32];
    SHA256d(buf, 64, h33);
    std::memcpy(buf, h12, 32);
    std::memcpy(buf + 32, h33, 32);
    uint8_t rootBytes[32];
    SHA256d(buf, 64, rootBytes);
    uint256 expected;
    expected.setBytesLE(rootBytes);
    CHECK(root == expected);
}
