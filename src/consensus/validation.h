#pragma once
#include <cstdint>
#include <string>
#include "transaction/transaction.h"
#include "blockchain/block.h"
#include "utxo/utxo-set.h"
#include "config/networks.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Validasi konsensus — deterministic.
// Node A, B, C harus menghasilkan hasil yang sama untuk block/tx yang sama.
// ---------------------------------------------------------------------------

struct TxValidationResult {
    bool ok = false;
    std::string error;
    int64_t fee = 0;
    bool isCoinbase = false;
};

// Validasi dasar format transaksi (tanpa konteks UTXO)
bool CheckTransaction(const CTransaction& tx, std::string& error);

// Validasi transaksi non-coinbase terhadap UTXO set:
//   - semua input ada dan belum dipakai
//   - signature valid
//   - sum(inputs) >= sum(outputs)
//   - bukan double spend
// Mengembalikan fee (inputSum - outputSum).
bool CheckTxInputs(const CTransaction& tx,
                   const CCoinsView& view,
                   int64_t height,
                   int64_t& fee,
                   std::string& error);

// Validasi penuh transaksi terhadap view + mempool (double spend)
bool ValidateTransaction(const CTransaction& tx,
                         const CCoinsView& view,
                         int64_t height,
                         int64_t& fee,
                         std::string& error,
                         bool checkCoinbase = false);

// Sighash: SHA256d dari serialized tx dengan scriptSig diganti scriptPubKey
// output yang di-spend (SIGHASH_ALL, version byte 1 appended).
uint256 SignatureHash(const CTransaction& tx, size_t inputIndex,
                      const std::vector<uint8_t>& scriptPubKey);

struct BlockValidationResult {
    bool ok = false;
    std::string error;
};

// Validasi header (PoW, prev, timestamp)
bool CheckBlockHeader(const CBlockHeader& hdr, const CBlockHeader* prev, const ChainParams& params,
                      std::string& error);

// Validasi penuh block: header + merkle + coinbase + semua tx + UTXO
// Mengembalikan fee total dan mensimulasikan perubahan UTXO pada view baru.
// NOTE: fungsi ini TIDAK memodifikasi view; pemanggil yang menerapkan.
bool CheckBlock(const CBlock& blk, int64_t height,
                const CCoinsView& view, const ChainParams& params,
                CCoinsView& viewOut, int64_t& fees, std::string& error);

} // namespace cdx
