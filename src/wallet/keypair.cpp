#include "wallet/keypair.h"
#include "wallet/address.h"
#include "crypto/hash.h"

namespace cdx {

CKeyPair CKeyPair::Generate(uint8_t versionByte) {
    CKeyPair kp;
    kp.key = CKey::Generate();
    kp.key.SetCompressed(true);
    kp.pubkeyLen = 33;
    kp.key.GetPubKeyCompressed(kp.pubkey);
    HASH160(kp.pubkey, kp.pubkeyLen, kp.hash160);
    kp.address = Hash160ToAddress(kp.hash160, versionByte);
    return kp;
}

CKeyPair CKeyPair::FromPrivKey(const uint8_t priv[32], uint8_t versionByte) {
    CKeyPair kp;
    if (!kp.key.SetPrivKey(priv, 32)) return kp;
    kp.key.SetCompressed(true);
    kp.pubkeyLen = 33;
    kp.key.GetPubKeyCompressed(kp.pubkey);
    HASH160(kp.pubkey, kp.pubkeyLen, kp.hash160);
    kp.address = Hash160ToAddress(kp.hash160, versionByte);
    return kp;
}

std::string CKeyPair::GetWIF(uint8_t versionByte) const {
    uint8_t priv[32];
    GetPrivKey(priv);
    std::string w = PrivKeyToWIF(priv, versionByte);
    std::memset(priv, 0, 32);
    return w;
}

} // namespace cdx
