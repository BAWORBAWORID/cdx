#pragma once
#include "wallet/wallet.h"
#include "blockchain/blockchain.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Wallet recovery — rescan blockchain untuk alamat wallet.
// Menemukan: incoming outputs, change outputs, spent outputs, UTXO.
// TIDAK ada admin recovery / master recovery key / seed phrase recovery.
// ---------------------------------------------------------------------------

// scan seluruh chain; mengisi history wallet dengan transaksi yang melibatkan
// alamat wallet. Mengembalikan jumlah transaksi ditemukan.
int64_t WalletRescan(CWallet& wallet, CBlockchain& blockchain, std::string& error);

} // namespace cdx
