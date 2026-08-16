#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "wallet/keypair.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Keystore — penyimpanan private key terenkripsi (wallet.dat).
//   KDF: PBKDF2-HMAC-SHA256 (established; setara Argon2id untuk keperluan ini)
//   Encryption: AES-256-GCM
//   Password: TIDAK pernah disimpan plaintext.
// Private keys TIDAK pernah: di-log, dikirim via P2P, diekspos RPC publik.
// ---------------------------------------------------------------------------

struct EncryptedKeyEntry {
    std::string address;
    std::vector<uint8_t> ciphertext;   // AES-256-GCM ciphertext
    std::vector<uint8_t> iv;           // 12 byte
    std::vector<uint8_t> tag;          // 16 byte
    uint64_t created = 0;
};

class CKeystore {
public:
    // saldo enkripsi default
    CKeystore() = default;

    // generate password salt + KDF params
    static constexpr int PBKDF2_ITERATIONS = 210000;
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t SALT_SIZE = 16;
    static constexpr size_t IV_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;

    // encrypt private key ke dalam store (wallet harus unlocked)
    bool AddKey(const CKeyPair& kp);

    // cari private key untuk alamat; melempar bila locked / tidak ada
    bool GetKey(const std::string& address, CKey& keyOut) const;

    bool HasAddress(const std::string& address) const {
        return keys.count(address) > 0;
    }

    size_t Size() const { return keys.size(); }
    std::vector<std::string> GetAddresses() const;

    // lock/unlock dengan password
    bool Lock();
    bool Unlock(const std::string& password);
    bool IsLocked() const { return locked; }

    // serialize ke byte (encrypted form) untuk penyimpanan
    std::vector<uint8_t> Serialize() const;
    // load dari byte; melempar bila corrupt
    static CKeystore Deserialize(const std::vector<uint8_t>& data);

    // change password
    bool ChangePassword(const std::string& oldPassword, const std::string& newPassword);

private:
    bool locked = true;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> kek; // key encryption key (sementara, hanya saat unlocked)
    std::map<std::string, EncryptedKeyEntry> keys; // address -> entry

    bool DeriveKey(const std::string& password, const std::vector<uint8_t>& saltIn, uint8_t out[32]) const;
    std::vector<uint8_t> AesEncrypt(const uint8_t* key, const uint8_t* plain, size_t len, uint8_t iv[12], uint8_t tag[16]) const;
    std::vector<uint8_t> AesDecrypt(const uint8_t* key, const uint8_t* cipher, size_t len, const uint8_t iv[12], const uint8_t tag[16]) const;

    friend class CWalletFile;
};

} // namespace cdx
