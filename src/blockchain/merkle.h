#pragma once
#include <vector>
#include "crypto/uint256.h"
#include "transaction/transaction.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Merkle tree: hashing berpasangan SHA256d.
// Jika jumlah node ganjil, node terakhir diduplikasi.
// Root dari satu transaksi = txid transaksi itu sendiri.
// ---------------------------------------------------------------------------
uint256 ComputeMerkleRoot(const std::vector<uint256>& hashes);

// Merkle root dari daftar transaksi (menggunakan txid)
uint256 ComputeMerkleRoot(const std::vector<CTransaction>& txs);

} // namespace cdx
