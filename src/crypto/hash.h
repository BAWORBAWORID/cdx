#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "crypto/uint256.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Hash primitives — hanya menggunakan established algorithms.
// SHA-256, SHA-256d, HASH160 (RIPEMD-160(SHA-256(x))).
// ---------------------------------------------------------------------------

// SHA-256 single-shot
void SHA256(const uint8_t* data, size_t len, uint8_t out[32]);

// SHA-256d (double SHA-256) — hash utama CDX
void SHA256d(const uint8_t* data, size_t len, uint8_t out[32]);
uint256 SHA256d(const uint8_t* data, size_t len);

// SHA-256 untuk data gabungan (chunk)
void SHA256TwoParts(const uint8_t* a, size_t alen, const uint8_t* b, size_t blen, uint8_t out[32]);

// RIPEMD-160
void RIPEMD160(const uint8_t* data, size_t len, uint8_t out[20]);

// HASH160 = RIPEMD160(SHA256(data))
void HASH160(const uint8_t* data, size_t len, uint8_t out[20]);
uint160 HASH160(const uint8_t* data, size_t len);

// HMAC-SHA256 (digunakan RFC6979)
void HMAC_SHA256(const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msglen, uint8_t out[32]);

// helper hex
std::string toHex(const uint8_t* data, size_t len);
std::string toHex(const std::vector<uint8_t>& v);

} // namespace cdx
