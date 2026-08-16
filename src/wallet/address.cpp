#include "wallet/address.h"
#include "crypto/hash.h"
#include "crypto/encoding.h"
#include "crypto/keys.h"
#include "script/interpreter.h"

namespace cdx {

std::string PubKeyToAddress(const uint8_t* pubkey, size_t len, uint8_t versionByte) {
    uint8_t h[20];
    HASH160(pubkey, len, h);
    return Hash160ToAddress(h, versionByte);
}

std::string Hash160ToAddress(const uint8_t hash160[20], uint8_t versionByte) {
    std::vector<uint8_t> payload;
    payload.reserve(21);
    payload.push_back(versionByte);
    payload.insert(payload.end(), hash160, hash160 + 20);
    return EncodeBase58Check(payload.data(), payload.size());
}

bool DecodeAddress(const std::string& address, uint8_t& versionByte, uint8_t hash160[20]) {
    try {
        auto payload = DecodeBase58Check(address);
        if (payload.size() != 21) return false;
        versionByte = payload[0];
        std::memcpy(hash160, payload.data() + 1, 20);
        return true;
    } catch (...) {
        return false;
    }
}

bool IsValidAddress(const std::string& address) {
    uint8_t v, h[20];
    return DecodeAddress(address, v, h);
}

std::string PrivKeyToWIF(const uint8_t priv[32], uint8_t versionByte) {
    std::vector<uint8_t> payload;
    payload.reserve(34);
    payload.push_back(versionByte);
    payload.insert(payload.end(), priv, priv + 32);
    payload.push_back(0x01); // compressed pubkey flag
    return EncodeBase58Check(payload.data(), payload.size());
}

bool WIFToPrivKey(const std::string& wif, uint8_t& versionByte, uint8_t priv[32]) {
    try {
        auto payload = DecodeBase58Check(wif);
        if (payload.size() != 34) return false;
        versionByte = payload[0];
        std::memcpy(priv, payload.data() + 1, 32);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace cdx
