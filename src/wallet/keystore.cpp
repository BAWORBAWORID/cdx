#include "wallet/keystore.h"
#include "crypto/keys.h"
#include "crypto/encoding.h"
#include "crypto/uint256.h"
#include "transaction/serializer.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <cstring>
#include <ctime>
#include <stdexcept>

namespace cdx {

namespace {
const uint8_t KEYSTORE_MAGIC[4] = {'C', 'D', 'X', 'W'};
const uint8_t KEYSTORE_VERSION = 1;
} // namespace

bool CKeystore::DeriveKey(const std::string& password, const std::vector<uint8_t>& saltIn, uint8_t out[32]) const {
    // PBKDF2-HMAC-SHA256 — established KDF (setara Argon2id untuk wallet ini)
    // PKCS5_PBKDF2_HMAC adalah API OpenSSL yang stable.
    return PKCS5_PBKDF2_HMAC(password.data(), (int)password.size(),
                             saltIn.data(), (int)saltIn.size(),
                             PBKDF2_ITERATIONS, EVP_sha256(),
                             KEY_SIZE, out) == 1;
}

std::vector<uint8_t> CKeystore::AesEncrypt(const uint8_t* key, const uint8_t* plain, size_t len, uint8_t iv[12], uint8_t tag[16]) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> out(len + 16);
    int outl = 0, finl = 0;
    if (!ctx) throw std::runtime_error("EVP ctx alloc failed");
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, out.data(), &outl, plain, (int)len) != 1 ||
        EVP_EncryptFinal_ex(ctx, out.data() + outl, &finl) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-256-GCM encrypt failed");
    }
    EVP_CIPHER_CTX_free(ctx);
    out.resize((size_t)outl + finl);
    return out;
}

std::vector<uint8_t> CKeystore::AesDecrypt(const uint8_t* key, const uint8_t* cipher, size_t len, const uint8_t iv[12], const uint8_t tag[16]) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> out(len + 16);
    int outl = 0, finl = 0;
    if (!ctx) throw std::runtime_error("EVP ctx alloc failed");
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, out.data(), &outl, cipher, (int)len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, out.data() + outl, &finl) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-256-GCM decrypt failed (wrong password?)");
    }
    EVP_CIPHER_CTX_free(ctx);
    out.resize((size_t)outl + finl);
    return out;
}

bool CKeystore::AddKey(const CKeyPair& kp) {
    if (locked) return false;
    uint8_t priv[32];
    kp.GetPrivKey(priv);
    uint8_t iv[IV_SIZE], tag[TAG_SIZE];
    RAND_bytes(iv, IV_SIZE);
    auto cipher = AesEncrypt(kek.data(), priv, 32, iv, tag);
    std::memset(priv, 0, 32);
    EncryptedKeyEntry e;
    e.address = kp.address;
    e.ciphertext = std::move(cipher);
    e.iv.assign(iv, iv + IV_SIZE);
    e.tag.assign(tag, tag + TAG_SIZE);
    e.created = (uint64_t)time(nullptr);
    keys[kp.address] = std::move(e);
    return true;
}

bool CKeystore::GetKey(const std::string& address, CKey& keyOut) const {
    if (locked) return false;
    auto it = keys.find(address);
    if (it == keys.end()) return false;
    auto plain = AesDecrypt(kek.data(), it->second.ciphertext.data(), it->second.ciphertext.size(),
                            it->second.iv.data(), it->second.tag.data());
    if (plain.size() != 32) return false;
    if (!keyOut.SetPrivKey(plain.data(), 32)) return false;
    std::memset(plain.data(), 0, plain.size());
    return true;
}

std::vector<std::string> CKeystore::GetAddresses() const {
    std::vector<std::string> out;
    out.reserve(keys.size());
    for (const auto& kv : keys) out.push_back(kv.first);
    return out;
}

bool CKeystore::Lock() {
    if (!kek.empty()) std::memset(kek.data(), 0, kek.size());
    kek.clear();
    locked = true;
    return true;
}

bool CKeystore::Unlock(const std::string& password) {
    if (salt.empty()) {
        // wallet baru tanpa salt: inisialisasi
        salt.resize(SALT_SIZE);
        RAND_bytes(salt.data(), SALT_SIZE);
    }
    uint8_t k[KEY_SIZE];
    if (!DeriveKey(password, salt, k)) return false;
    // verifikasi password dengan mencoba mendekripsi key pertama (jika ada)
    if (!keys.empty()) {
        auto it = keys.begin();
        try {
            auto plain = AesDecrypt(k, it->second.ciphertext.data(), it->second.ciphertext.size(),
                                    it->second.iv.data(), it->second.tag.data());
            if (plain.size() != 32) { std::memset(k, 0, 32); return false; }
            std::memset(plain.data(), 0, plain.size());
        } catch (...) {
            std::memset(k, 0, 32);
            return false;
        }
    }
    kek.assign(k, k + KEY_SIZE);
    std::memset(k, 0, KEY_SIZE);
    locked = false;
    return true;
}

bool CKeystore::ChangePassword(const std::string& oldPassword, const std::string& newPassword) {
    if (locked) {
        if (!Unlock(oldPassword)) return false;
    }
    // re-encrypt semua key dengan kek baru
    std::vector<CKey> keysCopy;
    std::vector<std::string> addrs = GetAddresses();
    for (const auto& a : addrs) {
        CKey k;
        if (!GetKey(a, k)) { Lock(); return false; }
        keysCopy.push_back(k);
    }
    // derive kek baru
    std::vector<uint8_t> newSalt(SALT_SIZE);
    RAND_bytes(newSalt.data(), SALT_SIZE);
    uint8_t newKek[KEY_SIZE];
    if (!DeriveKey(newPassword, newSalt, newKek)) { Lock(); return false; }
    kek.assign(newKek, newKek + KEY_SIZE);
    std::memset(newKek, 0, KEY_SIZE);
    salt = newSalt;
    keys.clear();
    for (size_t i = 0; i < addrs.size(); ++i) {
        uint8_t priv[32];
        keysCopy[i].GetPrivKey(priv);
        uint8_t iv[IV_SIZE], tag[TAG_SIZE];
        RAND_bytes(iv, IV_SIZE);
        auto cipher = AesEncrypt(kek.data(), priv, 32, iv, tag);
        std::memset(priv, 0, 32);
        EncryptedKeyEntry e;
        e.address = addrs[i];
        e.ciphertext = std::move(cipher);
        e.iv.assign(iv, iv + IV_SIZE);
        e.tag.assign(tag, tag + TAG_SIZE);
        e.created = (uint64_t)time(nullptr);
        keys[addrs[i]] = std::move(e);
    }
    return true;
}

std::vector<uint8_t> CKeystore::Serialize() const {
    CSerializer s;
    s.WriteBytes(KEYSTORE_MAGIC, 4);
    s.WriteU8(KEYSTORE_VERSION);
    s.WriteVarStr(salt);
    s.WriteVarInt(keys.size());
    for (const auto& kv : keys) {
        const auto& e = kv.second;
        s.WriteVarStr((const std::vector<uint8_t>&)std::vector<uint8_t>(e.address.begin(), e.address.end()));
        s.WriteVarStr(e.ciphertext);
        s.WriteVarStr(e.iv);
        s.WriteVarStr(e.tag);
        s.WriteU64(e.created);
    }
    return std::move(s.buf);
}

CKeystore CKeystore::Deserialize(const std::vector<uint8_t>& data) {
    CKeystore ks;
    CDeserializer d(data.data(), data.size());
    uint8_t magic[4];
    if (!d.ReadBytes(magic, 4) || std::memcmp(magic, KEYSTORE_MAGIC, 4) != 0)
        throw std::runtime_error("invalid keystore magic");
    uint8_t ver;
    if (!d.ReadU8(ver) || ver != KEYSTORE_VERSION)
        throw std::runtime_error("unsupported keystore version");
    if (!d.ReadVarStr(ks.salt)) throw std::runtime_error("corrupt keystore");
    uint64_t n;
    if (!d.ReadVarInt(n) || n > 1000000) throw std::runtime_error("corrupt keystore");
    for (uint64_t i = 0; i < n; ++i) {
        std::vector<uint8_t> addrBytes, cipher, iv, tag;
        uint64_t created;
        if (!d.ReadVarStr(addrBytes) || !d.ReadVarStr(cipher) || !d.ReadVarStr(iv) ||
            !d.ReadVarStr(tag) || !d.ReadU64(created))
            throw std::runtime_error("corrupt keystore entry");
        EncryptedKeyEntry e;
        e.address.assign(addrBytes.begin(), addrBytes.end());
        e.ciphertext = std::move(cipher);
        e.iv = std::move(iv);
        e.tag = std::move(tag);
        e.created = created;
        ks.keys[e.address] = std::move(e);
    }
    return ks;
}

} // namespace cdx
