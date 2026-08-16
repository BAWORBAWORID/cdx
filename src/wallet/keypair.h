#pragma once
#include <cstdint>
#include <string>
#include "crypto/keys.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Keypair — satu private key + public key + address.
// TIDAK ada derivasi hierarkis: setiap keypair independen (bukan HD).
// Tidak ada: BIP-32, BIP-39, BIP-44, seed phrase, master key.
// ---------------------------------------------------------------------------
struct CKeyPair {
    CKey key;                       // secp256k1 keypair
    uint8_t pubkey[33] = {0};       // compressed
    size_t pubkeyLen = 0;
    std::string address;            // CDX address
    uint8_t hash160[20] = {0};

    // generate keypair baru dari secure random
    static CKeyPair Generate(uint8_t versionByte);

    // bangun dari private key byte
    static CKeyPair FromPrivKey(const uint8_t priv[32], uint8_t versionByte);

    bool IsValid() const { return key.IsValid(); }

    void GetPrivKey(uint8_t out[32]) const { key.GetPrivKey(out); }
    std::string GetWIF(uint8_t versionByte) const;

    // address label
    std::string Label() const { return address; }
};

} // namespace cdx
