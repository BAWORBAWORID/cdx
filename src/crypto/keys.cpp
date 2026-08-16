#include "crypto/keys.h"
#include "crypto/hash.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <cstring>
#include <stdexcept>

namespace cdx {

namespace {
const EC_GROUP* Secp256k1Group() {
    static const EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_secp256k1);
    return g;
}
} // namespace

struct CKey::Impl {
    BIGNUM* priv = nullptr;
    EC_KEY* ec = nullptr;

    Impl() {
        priv = BN_new();
        ec = EC_KEY_new();
        EC_KEY_set_group(ec, Secp256k1Group());
        EC_KEY_set_conv_form(ec, POINT_CONVERSION_COMPRESSED);
    }
    ~Impl() {
        if (priv) { BN_clear_free(priv); }
        if (ec) { EC_KEY_free(ec); }
    }
};

CKey::CKey() : impl(new Impl()) {}
CKey::~CKey() = default;

CKey::CKey(const CKey& other) : impl(new Impl()), fCompressed(other.fCompressed), fValid(other.fValid) {
    if (other.impl->priv && fValid) {
        BN_copy(impl->priv, other.impl->priv);
        EC_KEY_set_private_key(impl->ec, impl->priv);
        // hitung ulang public key
        const EC_POINT* pub = EC_POINT_new(Secp256k1Group());
        if (pub) {
            if (EC_POINT_mul(Secp256k1Group(), (EC_POINT*)pub, impl->priv, nullptr, nullptr, nullptr) == 1)
                EC_KEY_set_public_key(impl->ec, pub);
            EC_POINT_free((EC_POINT*)pub);
        }
    }
}

CKey& CKey::operator=(const CKey& other) {
    if (this == &other) return *this;
    impl = std::make_unique<Impl>();
    fCompressed = other.fCompressed;
    fValid = other.fValid;
    if (other.impl->priv && fValid) {
        BN_copy(impl->priv, other.impl->priv);
        EC_KEY_set_private_key(impl->ec, impl->priv);
        const EC_POINT* pub = EC_POINT_new(Secp256k1Group());
        if (pub) {
            if (EC_POINT_mul(Secp256k1Group(), (EC_POINT*)pub, impl->priv, nullptr, nullptr, nullptr) == 1)
                EC_KEY_set_public_key(impl->ec, pub);
            EC_POINT_free((EC_POINT*)pub);
        }
    }
    return *this;
}

CKey::CKey(CKey&& other) noexcept = default;
CKey& CKey::operator=(CKey&& other) noexcept = default;

bool CKey::SetPrivKey(const uint8_t* p, size_t len) {
    if (len != 32) return false;
    BIGNUM* bn = BN_bin2bn(p, (int)len, nullptr);
    if (!bn) return false;
    const BIGNUM* order = EC_GROUP_get0_order(Secp256k1Group());
    if (BN_is_zero(bn) || BN_cmp(bn, order) >= 0) {
        BN_clear_free(bn);
        return false;
    }
    BN_clear(impl->priv);
    BN_copy(impl->priv, bn);
    BN_clear_free(bn);
    if (EC_KEY_set_private_key(impl->ec, impl->priv) != 1) return false;
    // hitung public key
    EC_POINT* pub = EC_POINT_new(Secp256k1Group());
    if (!pub) return false;
    bool ok = EC_POINT_mul(Secp256k1Group(), pub, impl->priv, nullptr, nullptr, nullptr) == 1 &&
              EC_KEY_set_public_key(impl->ec, pub) == 1;
    EC_POINT_free(pub);
    fValid = ok;
    return ok;
}

CKey CKey::Generate() {
    CKey k;
    for (int attempt = 0; attempt < 128; ++attempt) {
        uint8_t buf[32];
        if (RAND_bytes(buf, 32) != 1) throw std::runtime_error("RAND_bytes failed");
        // cek di range [1, n-1]
        if (k.SetPrivKey(buf, 32)) return k;
    }
    throw std::runtime_error("failed to generate valid private key");
}

bool CKey::IsValid() const { return fValid; }

void CKey::GetPrivKey(uint8_t out[32]) const {
    if (!fValid || !impl->priv) {
        std::memset(out, 0, 32);
        return;
    }
    BN_bn2binpad(impl->priv, out, 32);
}

bool CKey::GetPubKeyCompressed(uint8_t out[33]) const {
    if (!fValid) return false;
    const EC_POINT* pub = EC_KEY_get0_public_key(impl->ec);
    if (!pub) return false;
    // set compress form
    EC_KEY_set_conv_form(impl->ec, POINT_CONVERSION_COMPRESSED);
    size_t n = EC_POINT_point2oct(Secp256k1Group(), pub, POINT_CONVERSION_COMPRESSED, out, 33, nullptr);
    return n == 33;
}

bool CKey::GetPubKeyUncompressed(uint8_t out[65]) const {
    if (!fValid) return false;
    const EC_POINT* pub = EC_KEY_get0_public_key(impl->ec);
    if (!pub) return false;
    size_t n = EC_POINT_point2oct(Secp256k1Group(), pub, POINT_CONVERSION_UNCOMPRESSED, out, 65, nullptr);
    return n == 65;
}

// RFC6979 deterministic k — implementasi standar (HMAC-SHA256)
namespace {
void RFC6979_GenerateK(const uint8_t* priv32, const uint8_t* hash32,
                       const BIGNUM* order, BIGNUM* k_out) {
    // V = 0x01 * 32, K = 0x00 * 32
    uint8_t V[32], K[32];
    std::memset(V, 0x01, 32);
    std::memset(K, 0x00, 32);

    // K = HMAC(K, V || 0x00 || int2octets(x) || bits2octets(h1))
    // x = private key (32 byte)
    // h1 = hash (32 byte)
    {
        uint8_t msg[1 + 32 + 32];
        msg[0] = 0x00;
        std::memcpy(msg + 1, priv32, 32);
        std::memcpy(msg + 1 + 32, hash32, 32);
        HMAC_SHA256(K, 32, msg, sizeof(msg), K);
    }
    // V = HMAC(K, V)
    HMAC_SHA256(K, 32, V, 32, V);
    // K = HMAC(K, V || 0x01 || int2octets(x) || bits2octets(h1))
    {
        uint8_t msg[1 + 32 + 32];
        msg[0] = 0x01;
        std::memcpy(msg + 1, priv32, 32);
        std::memcpy(msg + 1 + 32, hash32, 32);
        HMAC_SHA256(K, 32, msg, sizeof(msg), K);
    }
    // V = HMAC(K, V)
    HMAC_SHA256(K, 32, V, 32, V);

    // loop: T = V; k = bits2int(T); if 1 <= k < n, done
    for (;;) {
        HMAC_SHA256(K, 32, V, 32, V);
        BIGNUM* kbn = BN_bin2bn(V, 32, nullptr);
        if (kbn) {
            if (!BN_is_zero(kbn) && BN_cmp(kbn, order) < 0) {
                BN_copy(k_out, kbn);
                BN_clear_free(kbn);
                return;
            }
            BN_clear_free(kbn);
        }
        // K = HMAC(K, V || 0x00)
        uint8_t msg[33];
        msg[0] = 0x00;
        std::memcpy(msg + 1, V, 32);
        HMAC_SHA256(K, 32, msg, 33, K);
        HMAC_SHA256(K, 32, V, 32, V);
    }
}
} // namespace

bool CKey::Sign(const uint8_t* hash32, size_t len, uint8_t* out, size_t& outlen) const {
    if (!fValid || len != 32) return false;
    uint8_t priv[32];
    GetPrivKey(priv);

    const BIGNUM* order = EC_GROUP_get0_order(Secp256k1Group());
    BIGNUM* k = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();
    BIGNUM* invk = BN_new();
    BIGNUM* z = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    bool ok = false;
    do {
        RFC6979_GenerateK(priv, hash32, order, k);
        // R = k*G; r = R.x mod n
        EC_POINT* R = EC_POINT_new(Secp256k1Group());
        if (!R) break;
        if (EC_POINT_mul(Secp256k1Group(), R, k, nullptr, nullptr, ctx) != 1) {
            EC_POINT_free(R);
            break;
        }
        BIGNUM* Rx = BN_new();
        if (EC_POINT_get_affine_coordinates(Secp256k1Group(), R, Rx, nullptr, ctx) != 1) {
            BN_clear_free(Rx);
            EC_POINT_free(R);
            break;
        }
        BN_nnmod(r, Rx, order, ctx);
        BN_clear_free(Rx);
        EC_POINT_free(R);
        if (BN_is_zero(r)) continue;

        // z = bits2int(hash) mod n
        BIGNUM* ztmp = BN_bin2bn(hash32, 32, nullptr);
        BN_nnmod(z, ztmp, order, ctx);
        BN_clear_free(ztmp);

        // s = k^-1 (z + r*d) mod n
        BN_mod_inverse(invk, k, order, ctx);
        BN_mod_mul(s, r, impl->priv, order, ctx);
        BN_mod_add(s, s, z, order, ctx);
        BN_mod_mul(s, s, invk, order, ctx);
        if (BN_is_zero(s)) continue;

        // low-S normalization (anti malleability)
        BIGNUM* halfOrder = BN_dup(order);
        BN_rshift1(halfOrder, order);
        if (BN_cmp(s, halfOrder) > 0) {
            BN_sub(s, order, s);
        }
        BN_clear_free(halfOrder);

        // encode DER: 0x30 len 0x02 rlen r 0x02 slen s
        uint8_t rb[33], sb[33];
        int rl = BN_bn2binpad(r, rb, 33);
        int sl = BN_bn2binpad(s, sb, 33);
        // trim leading zeros
        int rstart = 0, sstart = 0;
        while (rstart < rl - 1 && rb[rstart] == 0 && (rb[rstart + 1] & 0x80) == 0) ++rstart;
        while (sstart < sl - 1 && sb[sstart] == 0 && (sb[sstart + 1] & 0x80) == 0) ++sstart;
        int rlen = rl - rstart, slen = sl - sstart;
        // tambah leading 0x00 bila MSB high
        size_t total = 2 + 2 + rlen + 2 + slen;
        if (rb[rstart] & 0x80) ++total;
        if (sb[sstart] & 0x80) ++total;
        if (total > SIGNATURE_DER_MAX_SIZE) break;
        size_t pos = 0;
        out[pos++] = 0x30;
        out[pos++] = (uint8_t)(total - 2);
        out[pos++] = 0x02;
        if (rb[rstart] & 0x80) out[pos++] = (uint8_t)(rlen + 1), out[pos++] = 0x00;
        else out[pos++] = (uint8_t)rlen;
        std::memcpy(out + pos, rb + rstart, rlen); pos += rlen;
        out[pos++] = 0x02;
        if (sb[sstart] & 0x80) out[pos++] = (uint8_t)(slen + 1), out[pos++] = 0x00;
        else out[pos++] = (uint8_t)slen;
        std::memcpy(out + pos, sb + sstart, slen); pos += slen;
        outlen = pos;
        ok = true;
    } while (!ok);
    BN_clear_free(k);
    BN_clear_free(r);
    BN_clear_free(s);
    BN_clear_free(invk);
    BN_clear_free(z);
    BN_CTX_free(ctx);
    std::memset(priv, 0, 32);
    return ok;
}

bool VerifySignature(const uint8_t* hash32, size_t len,
                     const uint8_t* sig, size_t siglen,
                     const uint8_t* pubkey, size_t pubkeylen) {
    if (len != 32 || siglen == 0 || pubkeylen == 0) return false;
    EC_KEY* ec = EC_KEY_new();
    if (!ec) return false;
    EC_KEY_set_group(ec, Secp256k1Group());
    // parse pubkey
    EC_POINT* point = EC_POINT_new(Secp256k1Group());
    bool ok = false;
    if (point) {
        if (EC_POINT_oct2point(Secp256k1Group(), point, pubkey, pubkeylen, nullptr) == 1 &&
            EC_KEY_set_public_key(ec, point) == 1) {
            ECDSA_SIG* sigObj = ECDSA_SIG_new();
            if (sigObj) {
                const uint8_t* p = sig;
                if (d2i_ECDSA_SIG(&sigObj, &p, (long)siglen)) {
                    ok = ECDSA_do_verify(hash32, (int)len, sigObj, ec) == 1;
                }
                ECDSA_SIG_free(sigObj);
            }
        }
        EC_POINT_free(point);
    }
    EC_KEY_free(ec);
    return ok;
}

bool CompressPubKey(const uint8_t* pubkey65, size_t len, uint8_t out33[33]) {
    if (len != 65) return false;
    EC_KEY* ec = EC_KEY_new();
    EC_KEY_set_group(ec, Secp256k1Group());
    EC_POINT* point = EC_POINT_new(Secp256k1Group());
    bool ok = false;
    if (point && EC_POINT_oct2point(Secp256k1Group(), point, pubkey65, 65, nullptr) == 1) {
        size_t n = EC_POINT_point2oct(Secp256k1Group(), point, POINT_CONVERSION_COMPRESSED, out33, 33, nullptr);
        ok = n == 33;
    }
    if (point) EC_POINT_free(point);
    EC_KEY_free(ec);
    return ok;
}

bool DecompressPubKey(const uint8_t* pubkey33, size_t len, uint8_t out65[65]) {
    if (len != 33) return false;
    EC_KEY* ec = EC_KEY_new();
    EC_KEY_set_group(ec, Secp256k1Group());
    EC_POINT* point = EC_POINT_new(Secp256k1Group());
    bool ok = false;
    if (point && EC_POINT_oct2point(Secp256k1Group(), point, pubkey33, 33, nullptr) == 1) {
        size_t n = EC_POINT_point2oct(Secp256k1Group(), point, POINT_CONVERSION_UNCOMPRESSED, out65, 65, nullptr);
        ok = n == 65;
    }
    if (point) EC_POINT_free(point);
    EC_KEY_free(ec);
    return ok;
}

} // namespace cdx
