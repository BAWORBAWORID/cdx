#include "wallet/signer.h"
#include "consensus/validation.h"
#include "crypto/hash.h"

namespace cdx {

bool SignInput(CTransaction& tx, size_t inputIndex,
               const CKeyPair& kp,
               const std::vector<uint8_t>& scriptPubKey,
               std::string& error) {
    if (inputIndex >= tx.vin.size()) {
        error = "input index out of range";
        return false;
    }
    uint256 sh = SignatureHash(tx, inputIndex, scriptPubKey);
    uint8_t hash32[32];
    sh.getBytesLE(hash32);
    uint8_t sig[72];
    size_t siglen = 0;
    if (!kp.key.Sign(hash32, 32, sig, siglen)) {
        error = "signing failed";
        return false;
    }
    // append sighash type byte
    std::vector<uint8_t> scriptSig;
    scriptSig.reserve(siglen + 1 + 33 + 2);
    scriptSig.push_back((uint8_t)(siglen + 1));
    scriptSig.insert(scriptSig.end(), sig, sig + siglen);
    scriptSig.push_back(0x01); // SIGHASH_ALL
    scriptSig.push_back(33);
    scriptSig.insert(scriptSig.end(), kp.pubkey, kp.pubkey + 33);
    tx.vin[inputIndex].scriptSig = std::move(scriptSig);
    return true;
}

bool SignTransaction(CTransaction& tx,
                     const CKeyPair& kp,
                     const std::vector<std::vector<uint8_t>>& scriptPubKeys,
                     std::string& error) {
    if (scriptPubKeys.size() != tx.vin.size()) {
        error = "scriptPubKey count mismatch";
        return false;
    }
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        if (!SignInput(tx, i, kp, scriptPubKeys[i], error)) return false;
    }
    return true;
}

} // namespace cdx
