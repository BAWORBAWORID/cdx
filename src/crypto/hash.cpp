#include "crypto/hash.h"
#include "crypto/ripemd160.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <cstring>
#include <stdexcept>

namespace cdx {

static void sha256_oneshot(const uint8_t* data, size_t len, uint8_t out[32]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, out, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA256 computation failed");
    }
    EVP_MD_CTX_free(ctx);
}

void SHA256(const uint8_t* data, size_t len, uint8_t out[32]) {
    sha256_oneshot(data, len, out);
}

void SHA256d(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t tmp[32];
    sha256_oneshot(data, len, tmp);
    sha256_oneshot(tmp, 32, out);
}

uint256 SHA256d(const uint8_t* data, size_t len) {
    uint8_t h[32];
    SHA256d(data, len, h);
    uint256 r;
    r.setBytesLE(h);
    return r;
}

void SHA256TwoParts(const uint8_t* a, size_t alen, const uint8_t* b, size_t blen, uint8_t out[32]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, a, alen) != 1 ||
        EVP_DigestUpdate(ctx, b, blen) != 1 ||
        EVP_DigestFinal_ex(ctx, out, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA256 computation failed");
    }
    EVP_MD_CTX_free(ctx);
}

void RIPEMD160(const uint8_t* data, size_t len, uint8_t out[20]) {
    ripemd160(data, len, out);
}

void HASH160(const uint8_t* data, size_t len, uint8_t out[20]) {
    uint8_t sha[32];
    sha256_oneshot(data, len, sha);
    ripemd160(sha, 32, out);
}

uint160 HASH160(const uint8_t* data, size_t len) {
    uint8_t h[20];
    HASH160(data, len, h);
    uint160 r;
    r.setBytes(h);
    return r;
}

void HMAC_SHA256(const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msglen, uint8_t out[32]) {
    unsigned int outlen = 32;
    if (!HMAC(EVP_sha256(), key, (int)keylen, msg, msglen, out, &outlen))
        throw std::runtime_error("HMAC-SHA256 failed");
}

std::string toHex(const uint8_t* data, size_t len) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        s.push_back(H[data[i] >> 4]);
        s.push_back(H[data[i] & 0xf]);
    }
    return s;
}

std::string toHex(const std::vector<uint8_t>& v) {
    return toHex(v.data(), v.size());
}

} // namespace cdx
