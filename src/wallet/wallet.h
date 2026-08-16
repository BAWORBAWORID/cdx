#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "wallet/keystore.h"
#include "wallet/keypair.h"
#include "utxo/utxo-set.h"
#include "transaction/transaction.h"
#include "config/networks.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Wallet — koleksi keypair independen (NON-HD).
// Setiap address memiliki private key sendiri; TIDAK ada derivasi.
// Balance dihitung dari UTXO set (blockchain = source of truth).
// ---------------------------------------------------------------------------

struct WalletTxRecord {
    uint256 txid;
    int64_t height = -1;   // -1 = belum dikonfirmasi (mempool)
    int64_t amount = 0;    // +/- base units
    int64_t fee = 0;
    std::string address;   // counterparty / change / self
    int64_t timestamp = 0;
    bool isCoinbase = false;
};

class CWallet {
public:
    CKeystore keystore;
    uint8_t versionByte = 0x1E;

    // --- key management ---
    CKeyPair GenerateNewAddress();
    bool ImportKey(const CKeyPair& kp);
    bool ImportWIF(const std::string& wif);
    bool HasKey(const std::string& address) const;
    bool GetKey(const std::string& address, CKey& key) const { return keystore.GetKey(address, key); }

    std::vector<std::string> GetAddresses() const { return keystore.GetAddresses(); }
    size_t KeyCount() const { return keystore.Size(); }

    bool IsLocked() const { return keystore.IsLocked(); }
    bool Lock() { return keystore.Lock(); }
    bool Unlock(const std::string& password) { return keystore.Unlock(password); }
    bool ChangePassword(const std::string& oldP, const std::string& newP) { return keystore.ChangePassword(oldP, newP); }

    // --- balance (dari UTXO) ---
    struct Balance {
        int64_t confirmed = 0;
        int64_t unconfirmed = 0;
        int64_t immature = 0;
        int64_t spendable = 0;
    };
    Balance GetBalance(const CCoinsView& view, int64_t height) const;

    // --- UTXO selection (coin selection) ---
    struct SelectedInput {
        COutPoint outpoint;
        CUTXO coin;
        std::string address; // alamat pemilik (untuk ambil private key)
    };
    // pilih UTXO untuk membayar amount + fee; mengembalikan false bila saldo kurang
    bool SelectCoins(const CCoinsView& view, int64_t height, int64_t amountNeeded,
                     std::vector<SelectedInput>& selected) const;

    // --- send ---
    // Buat transaksi: inputs dari UTXO wallet, output penerima + change (keypair baru).
    // Fee otomatis (estimatesmartfee -> fallback DEFAULT_FEE_RATE).
    // Mengembalikan txid; txOut berisi tx siap broadcast.
    bool CreateTransaction(const CCoinsView& view, int64_t height,
                           const std::string& toAddress, int64_t amountBase,
                           CTransaction& txOut, uint256& txid,
                           std::string& error, int64_t* feeOut = nullptr);

    // --- history (dari scan block records) ---
    std::vector<WalletTxRecord> GetHistory() const { return history; }
    void AddRecord(const WalletTxRecord& r) { history.push_back(r); }

    // --- backup/restore ---
    // Enkripsi seluruh private keys ke file backup (menggunakan password wallet).
    std::vector<uint8_t> Backup(const std::string& password) const;
    static CWallet Restore(const std::vector<uint8_t>& backup, const std::string& password,
                           std::string& error);

private:
    std::vector<WalletTxRecord> history;

    int64_t EstimateFee(size_t txSizeBytes) const;
};

} // namespace cdx
