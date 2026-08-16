#pragma once
#include <string>
#include <vector>
#include "wallet/wallet.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Wallet backup/restore ke file.
//   cdx-cli wallet backup   -> cdx-wallet-backup.dat (encrypted)
//   cdx-cli wallet restore  -> decrypt + rescan + recover UTXO + balance
// Backup sangat penting karena TIDAK ada seed phrase.
// ---------------------------------------------------------------------------

// simpan backup ke file; mengembalikan path
std::string SaveBackupFile(const std::string& dataDir, const CWallet& wallet,
                           const std::string& password, std::string& error);

// load backup dari file dan restore wallet
CWallet LoadBackupFile(const std::string& path, const std::string& password, std::string& error);

} // namespace cdx
