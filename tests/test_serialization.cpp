#include "testfw.h"
#include "transaction/serializer.h"
#include "blockchain/block.h"
#include "crypto/encoding.h"
#include "crypto/hash.h"
#include <cstring>

using namespace cdx;

TEST(transaction_serialize_roundtrip) {
    CTransaction tx;
    tx.version = 1;
    CTxIn in;
    in.prevout.hash = uint256(0xdeadbeef);
    in.prevout.n = 3;
    in.scriptSig = {0x02, 0x01, 0x02};
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    CTxOut out;
    out.value = 100000000;
    out.scriptPubKey = {0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                        11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac};
    tx.vout.push_back(out);
    tx.lockTime = 0;

    auto ser = SerializeTransaction(tx);
    CHECK(ser.size() > 0);
    CTransaction tx2;
    CHECK(DeserializeTransaction(ser.data(), ser.size(), tx2));
    CHECK(tx2 == tx);
    CHECK(GetTxID(tx) == GetTxID(tx2));
}

TEST(transaction_deterministic_serialization) {
    CTransaction tx;
    tx.version = 1;
    CTxIn in;
    tx.vin.push_back(in);
    CTxOut out;
    out.value = 5;
    tx.vout.push_back(out);
    auto a = SerializeTransaction(tx);
    auto b = SerializeTransaction(tx);
    CHECK(a == b);
}

TEST(varint_roundtrip) {
    uint64_t vals[] = {0, 1, 0xfc, 0xfd, 0xffff, 0x10000, 0xffffffffull, 0x100000000ull};
    for (auto v : vals) {
        uint8_t buf[16];
        size_t n = WriteVarInt(buf, v);
        uint64_t out = 0;
        int r = ReadVarInt(buf, n, out);
        CHECK(r == (int)n);
        CHECK(out == v);
    }
}

TEST(block_header_serialize) {
    CBlockHeader hdr;
    hdr.version = 1;
    hdr.prevBlockHash = uint256(0x1234);
    hdr.merkleRoot = uint256(0x5678);
    hdr.timestamp = 1234567;
    hdr.bits = 0x1d00ffff;
    hdr.nonce = 42;
    auto ser = SerializeBlockHeader(hdr);
    CHECK(ser.size() == 80);
    CBlockHeader h2;
    CHECK(DeserializeBlockHeader(ser.data(), ser.size(), h2));
    CHECK(h2.timestamp == 1234567);
    CHECK(h2.bits == 0x1d00ffff);
    CHECK(h2.nonce == 42);
    CHECK(h2.prevBlockHash == hdr.prevBlockHash);
    CHECK(hdr.GetHash() == h2.GetHash());
}

TEST(hex_encoding) {
    std::vector<uint8_t> out;
    CHECK(DecodeHex("deadbeef", out));
    CHECK(out.size() == 4);
    CHECK(out[0] == 0xde && out[3] == 0xef);
    CHECK(!DecodeHex("xyz", out));
    CHECK(toHex(out.data(), 4) == "deadbeef");
}
