#pragma once
#include <cstdint>
#include <vector>
#include "transaction/transaction.h"
#include "wallet/keypair.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Signer — menandatangani input transaksi P2PKH.
// Sighash: SIGHASH_ALL (0x01).
// scriptSig = <sig DER> <pubkey compressed>
// ---------------------------------------------------------------------------

// tanda tangani semua input yang prevoutnya cocok dengan keypair ini
// (untuk tx dengan satu penerima; cukup untuk kasus umum)
bool SignTransaction(CTransaction& tx,
                     const CKeyPair& kp,
                     const std::vector<std::vector<uint8_t>>& scriptPubKeys,
                     std::string& error);

// versi per-input: sign input index tertentu
bool SignInput(CTransaction& tx, size_t inputIndex,
               const CKeyPair& kp,
               const std::vector<uint8_t>& scriptPubKey,
               std::string& error);

} // namespace cdx
