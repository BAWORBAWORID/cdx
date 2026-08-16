#pragma once
#include <cstdint>
#include <vector>
#include "crypto/uint256.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Script interpreter — subset bitcoin-style untuk P2PKH.
//   scriptPubKey: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
//   scriptSig:    <sig> <pubkey>
// ---------------------------------------------------------------------------

// Tanda tangan dihitung atas SHA256d dari serialized tx dengan scriptSig
// diganti scriptPubKey dari output yang di-spend (bitcoin sighash legacy).
// CDX hanya mendukung SIGHASH_ALL (0x01), deterministic.

struct ScriptExecutionResult {
    bool ok = false;
    std::string error;
    int64_t fee = 0; // (tidak dipakai di sini)
};

// Verifikasi: scriptSig terhadap scriptPubKey, hash 32-byte tx digest.
bool VerifyScript(const std::vector<uint8_t>& scriptSig,
                  const std::vector<uint8_t>& scriptPubKey,
                  const uint8_t* hash32,
                  std::string& error);

// Eksekusi script stack; dipakai internal & test.
bool EvalScript(const std::vector<uint8_t>& script,
                const uint8_t* hash32,
                std::vector<std::vector<uint8_t>>& stack,
                std::string& error);

// Bantuan membangun script
std::vector<uint8_t> BuildP2PKHScript(const uint8_t hash160[20]);
bool IsP2PKHScript(const std::vector<uint8_t>& script);
// Ekstrak hash160 dari P2PKH script; false bila bukan P2PKH
bool ExtractP2PKHHash(const std::vector<uint8_t>& script, uint8_t hash160[20]);

// jumlah elemen data push di scriptSig (biasanya 2: sig + pubkey)
void GetScriptSigPubKey(const std::vector<uint8_t>& scriptSig, std::vector<uint8_t>& pubkey);

} // namespace cdx
