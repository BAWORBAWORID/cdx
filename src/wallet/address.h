#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "config/networks.h"

namespace cdx {

// ---------------------------------------------------------------------------
// CDX Address — Base58Check.
//   payload = versionByte || HASH160(pubkey)
//   address = Base58Check(payload)
// Prefix versi berbeda untuk mainnet/testnet/regtest.
// ---------------------------------------------------------------------------

// encode alamat dari hash160 pubkey
std::string PubKeyToAddress(const uint8_t* pubkey, size_t len, uint8_t versionByte);
std::string Hash160ToAddress(const uint8_t hash160[20], uint8_t versionByte);

// decode alamat -> hash160; melempar std::runtime_error bila invalid
bool DecodeAddress(const std::string& address, uint8_t& versionByte, uint8_t hash160[20]);

// cek validitas alamat (tanpa melempar)
bool IsValidAddress(const std::string& address);

// WIF (Wallet Import Format) — private key terkompresi
std::string PrivKeyToWIF(const uint8_t priv[32], uint8_t versionByte);
bool WIFToPrivKey(const std::string& wif, uint8_t& versionByte, uint8_t priv[32]);

} // namespace cdx
