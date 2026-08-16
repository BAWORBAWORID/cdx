#include "testfw.h"
#include "crypto/hash.h"
#include "crypto/keys.h"
#include "crypto/encoding.h"
#include "crypto/uint256.h"
#include <cstring>

using namespace cdx;

TEST(sha256_known_vector) {
    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    uint8_t out[32];
    SHA256((const uint8_t*)"", 0, out);
    CHECK(toHex(out, 32) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    // SHA256("abc")
    SHA256((const uint8_t*)"abc", 3, out);
    CHECK(toHex(out, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(sha256d_double) {
    // SHA256d("hello") — verifikasi dengan menghitung manual via OpenSSL
    uint8_t out[32], tmp[32];
    SHA256((const uint8_t*)"hello", 5, tmp);
    SHA256(tmp, 32, out);
    uint8_t d[32];
    SHA256d((const uint8_t*)"hello", 5, d);
    CHECK(std::memcmp(out, d, 32) == 0);
}

TEST(hash160) {
    // HASH160("hello") = RIPEMD160(SHA256("hello"))
    uint8_t sha[32], out[20];
    SHA256((const uint8_t*)"hello", 5, sha);
    RIPEMD160(sha, 32, out);
    uint8_t h[20];
    HASH160((const uint8_t*)"hello", 5, h);
    CHECK(std::memcmp(out, h, 20) == 0);
}

TEST(ripemd160_known_vector) {
    // RIPEMD160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
    uint8_t out[20];
    RIPEMD160((const uint8_t*)"", 0, out);
    CHECK(toHex(out, 20) == "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    // RIPEMD160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
    RIPEMD160((const uint8_t*)"abc", 3, out);
    CHECK(toHex(out, 20) == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
}

TEST(secp256k1_sign_verify) {
    CKey k = CKey::Generate();
    CHECK(k.IsValid());
    uint8_t hash[32];
    for (int i = 0; i < 32; ++i) hash[i] = (uint8_t)i;
    uint8_t sig[72];
    size_t siglen = 0;
    CHECK(k.Sign(hash, 32, sig, siglen));
    CHECK(siglen > 0);
    uint8_t pub[33];
    CHECK(k.GetPubKeyCompressed(pub));
    CHECK(VerifySignature(hash, 32, sig, siglen, pub, 33));
    // salah hash -> gagal
    uint8_t bad[32];
    std::memcpy(bad, hash, 32);
    bad[0] ^= 1;
    CHECK(!VerifySignature(bad, 32, sig, siglen, pub, 33));
}

TEST(secp256k1_deterministic_rfc6979) {
    // RFC6979: tanda tangan harus deterministic untuk input yang sama
    CKey k = CKey::Generate();
    uint8_t hash[32] = {0};
    hash[0] = 0x42;
    uint8_t sig1[72], sig2[72];
    size_t l1 = 0, l2 = 0;
    CHECK(k.Sign(hash, 32, sig1, l1));
    CHECK(k.Sign(hash, 32, sig2, l2));
    CHECK(l1 == l2);
    CHECK(std::memcmp(sig1, sig2, l1) == 0);
}

TEST(privkey_roundtrip) {
    CKey k = CKey::Generate();
    uint8_t priv[32];
    k.GetPrivKey(priv);
    CKey k2;
    CHECK(k2.SetPrivKey(priv, 32));
    uint8_t pub1[33], pub2[33];
    k.GetPubKeyCompressed(pub1);
    k2.GetPubKeyCompressed(pub2);
    CHECK(std::memcmp(pub1, pub2, 33) == 0);
}

TEST(base58check_roundtrip) {
    uint8_t payload[21] = {0x1E};
    for (int i = 1; i < 21; ++i) payload[i] = (uint8_t)(i * 7);
    std::string enc = EncodeBase58Check(payload, 21);
    auto dec = DecodeBase58Check(enc);
    CHECK(dec.size() == 21);
    CHECK(std::memcmp(dec.data(), payload, 21) == 0);
    // checksum invalid
    std::string tampered = enc;
    tampered[0] = tampered[0] == '1' ? '2' : '1';
    bool threw = false;
    try { DecodeBase58Check(tampered); } catch (...) { threw = true; }
    CHECK(threw);
}

TEST(base58_known_vector) {
    // base58 dari "hello world" (bitcoin test vector)
    std::vector<uint8_t> data{'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
    std::string enc = EncodeBase58(data.data(), data.size());
    CHECK(enc == "StV1DL6CwTryKyV");
}

TEST(uint256_hex) {
    uint256 v = uint256::fromHex("0000000000000000000000000000000000000000000000000000000000000001");
    CHECK(v.w[0] == 1);
    CHECK(v.getHex() == "0000000000000000000000000000000000000000000000000000000000000001");
}

TEST(uint256_compact) {
    // 0x1d00ffff -> target bitcoin genesis
    uint256 t = uint256::setCompact(0x1d00ffffu);
    CHECK(!t.isZero());
    uint32_t bits = t.getCompact();
    CHECK(bits == 0x1d00ffffu);
}

TEST(chainwork) {
    // chain work = 2^256 / (target+1) — harus > 0
    uint256 target = uint256::setCompact(0x1d00ffffu);
    uint256 work = uint256::chainWorkOfTarget(target);
    CHECK(!work.isZero());
    // target lebih kecil -> work lebih besar
    uint256 harder = target >> 1;
    uint256 work2 = uint256::chainWorkOfTarget(harder);
    CHECK(work2 > work);
}
