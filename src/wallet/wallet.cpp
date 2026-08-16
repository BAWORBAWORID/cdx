#include "wallet/wallet.h"
#include "wallet/address.h"
#include "wallet/signer.h"
#include "consensus/validation.h"
#include "consensus/policy.h"
#include "script/interpreter.h"
#include "transaction/serializer.h"
#include "crypto/hash.h"
#include "crypto/encoding.h"
#include "crypto/uint256.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <stdexcept>

namespace cdx {

CKeyPair CWallet::GenerateNewAddress() {
    CKeyPair kp = CKeyPair::Generate(versionByte);
    keystore.AddKey(kp);
    return kp;
}

bool CWallet::ImportKey(const CKeyPair& kp) {
    if (kp.address.empty()) return false;
    return keystore.AddKey(kp);
}

bool CWallet::ImportWIF(const std::string& wif) {
    uint8_t version, priv[32];
    if (!WIFToPrivKey(wif, version, priv)) return false;
    CKeyPair kp = CKeyPair::FromPrivKey(priv, versionByte);
    std::memset(priv, 0, 32);
    return ImportKey(kp);
}

bool CWallet::HasKey(const std::string& address) const {
    return keystore.HasAddress(address);
}

CWallet::Balance CWallet::GetBalance(const CCoinsView& view, int64_t height) const {
    Balance bal;
    for (const auto& addr : GetAddresses()) {
        uint8_t v, h[20];
        if (!DecodeAddress(addr, v, h)) continue;
        if (v != versionByte) continue;
        int64_t conf = 0, unconf = 0, imm = 0;
        view.GetAddressBalance(h, height, conf, unconf, imm);
        bal.confirmed += conf;
        bal.unconfirmed += unconf;
        bal.immature += imm;
    }
    bal.spendable = bal.confirmed;
    return bal;
}

bool CWallet::SelectCoins(const CCoinsView& view, int64_t height, int64_t amountNeeded,
                          std::vector<SelectedInput>& selected) const {
    // kumpulkan semua UTXO milik wallet, urutkan ascending value
    struct Entry {
        COutPoint outpoint;
        CUTXO coin;
        std::string address;
    };
    std::vector<Entry> entries;
    for (const auto& addr : GetAddresses()) {
        uint8_t v, h[20];
        if (!DecodeAddress(addr, v, h)) continue;
        if (v != versionByte) continue;
        for (const auto& kv : view.utxo) {
            uint8_t hh[20];
            if (!ExtractP2PKHHash(kv.second.scriptPubKey, hh)) continue;
            if (std::memcmp(hh, h, 20) != 0) continue;
            if (!kv.second.IsSpendable(height)) continue;
            entries.push_back({kv.first, kv.second, addr});
        }
    }
    std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
        return a.coin.value < b.coin.value;
    });

    int64_t total = 0;
    selected.clear();
    for (const auto& e : entries) {
        selected.push_back({e.outpoint, e.coin, e.address});
        total += e.coin.value;
        if (total >= amountNeeded) return true;
    }
    return false;
}

int64_t CWallet::EstimateFee(size_t txSizeBytes) const {
    // estimatesmartfee: fallback DEFAULT_FEE_RATE (base units / byte)
    int64_t rate = DEFAULT_FEE_RATE;
    // policy fee dikonversi: DEFAULT_FEE_RATE per 1000 byte (per KB)
    int64_t fee = (int64_t)((uint64_t)txSizeBytes * (uint64_t)DEFAULT_FEE_RATE / 1000);
    if (fee < 100) fee = 100; // fee minimum 0.000001 CDX
    (void)rate;
    return fee;
}

bool CWallet::CreateTransaction(const CCoinsView& view, int64_t height,
                                const std::string& toAddress, int64_t amountBase,
                                CTransaction& txOut, uint256& txid,
                                std::string& error, int64_t* feeOut) {
    if (IsLocked()) { error = "wallet is locked"; return false; }
    uint8_t toVersion, toHash[20];
    if (!DecodeAddress(toAddress, toVersion, toHash)) {
        error = "invalid recipient address";
        return false;
    }
    if (amountBase <= 0) { error = "amount must be positive"; return false; }

    // coba build dengan perkiraan ukuran; ulangi hingga muat
    const int maxAttempts = 8;
    for (int attempt = 0; attempt < maxAttempts; ++attempt) {
        // ukuran perkiraan: 10 + vin*(32+4+~107+4) + vout*(8+~25) + 4
        size_t approxSize = 10 + 3 * (32 + 4 + 110 + 4) + 2 * (8 + 25) + 4;
        if (attempt > 0) approxSize += 150; // growth margin
        int64_t fee = EstimateFee(approxSize);
        int64_t amountNeeded = amountBase + fee;

        std::vector<SelectedInput> selected;
        if (!SelectCoins(view, height, amountNeeded, selected)) {
            error = "insufficient funds (need " + FormatValue(amountNeeded) + ")";
            return false;
        }

        int64_t inSum = 0;
        for (const auto& s : selected) inSum += s.coin.value;
        int64_t change = inSum - amountNeeded;

        CTransaction tx;
        tx.version = 1;
        tx.lockTime = 0;
        for (const auto& s : selected) {
            CTxIn in;
            in.prevout = s.outpoint;
            in.sequence = 0xffffffff;
            tx.vin.push_back(in);
        }
        // output penerima
        CTxOut out;
        out.value = amountBase;
        out.scriptPubKey = BuildP2PKHScript(toHash);
        tx.vout.push_back(out);

        // change: keypair independen baru (bukan derivasi!)
        if (change > 0) {
            // dust rule: jangan buat change terlalu kecil; sisanya jadi fee
            if (change < 1000) {
                fee += change;
                change = 0;
            } else {
                CKeyPair changeKp = GenerateNewAddress(); // disimpan di wallet
                uint8_t ch[20];
                if (!DecodeAddress(changeKp.address, toVersion, ch)) continue;
                CTxOut cOut;
                cOut.value = change;
                cOut.scriptPubKey = BuildP2PKHScript(ch);
                tx.vout.push_back(cOut);
            }
        }
        // pastikan fee valid: inSum - outSum == fee
        int64_t outSum = 0;
        for (const auto& o : tx.vout) outSum += o.value;
        int64_t actualFee = inSum - outSum;
        if (actualFee < 0) { error = "internal: negative fee"; return false; }

        // sign semua input
        std::vector<std::vector<uint8_t>> scripts;
        for (const auto& s : selected) scripts.push_back(s.coin.scriptPubKey);
        std::vector<CKeyPair> kps;
        for (const auto& s : selected) {
            CKey key;
            if (!GetKey(s.address, key)) {
                error = "missing private key for " + s.address;
                return false;
            }
            CKeyPair kp;
            kp.key = key;
            kp.pubkeyLen = 33;
            key.GetPubKeyCompressed(kp.pubkey);
            HASH160(kp.pubkey, 33, kp.hash160);
            kp.address = s.address;
            kps.push_back(kp);
        }
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            if (!SignInput(tx, i, kps[i], scripts[i], error)) return false;
        }

        // validasi lokal
        int64_t vfee = 0;
        std::string verr;
        if (!ValidateTransaction(tx, view, height, vfee, verr)) {
            error = verr;
            return false;
        }
        txOut = std::move(tx);
        txid = GetTxID(txOut);
        if (feeOut) *feeOut = actualFee;
        return true;
    }
    error = "could not construct transaction";
    return false;
}

// ---------------------------------------------------------------------------
// Backup: enkripsi semua private keys dengan password (AES-256-GCM + PBKDF2).
// Format: magic "CDXB" + version + salt + entries(addr, cipher, iv, tag)
// ---------------------------------------------------------------------------
namespace {
const uint8_t BACKUP_MAGIC[4] = {'C', 'D', 'X', 'B'};
} // namespace

std::vector<uint8_t> CWallet::Backup(const std::string& password) const {
    // ambil semua private keys
    std::vector<std::pair<std::string, std::vector<uint8_t>>> keys;
    for (const auto& addr : GetAddresses()) {
        CKey k;
        if (!keystore.GetKey(addr, k)) continue;
        uint8_t priv[32];
        k.GetPrivKey(priv);
        keys.push_back({addr, std::vector<uint8_t>(priv, priv + 32)});
        std::memset(priv, 0, 32);
    }

    std::vector<uint8_t> salt(16);
    RAND_bytes(salt.data(), 16);
    // derive key dari password (PBKDF2-HMAC-SHA256, established)
    uint8_t kek[32];
    if (PKCS5_PBKDF2_HMAC(password.data(), (int)password.size(),
                          salt.data(), (int)salt.size(),
                          210000, EVP_sha256(), 32, kek) != 1) {
        throw std::runtime_error("KDF failed");
    }

    CSerializer s;
    s.WriteBytes(BACKUP_MAGIC, 4);
    s.WriteU8(1);
    s.WriteVarStr(salt);
    s.WriteVarInt(keys.size());
    for (auto& kv : keys) {
        uint8_t iv[12], tag[16];
        RAND_bytes(iv, 12);
        EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
        std::vector<uint8_t> cipher(32 + 16);
        int outl = 0, finl = 0;
        bool ok = EVP_EncryptInit_ex(ectx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                  EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
                  EVP_EncryptInit_ex(ectx, nullptr, nullptr, kek, iv) == 1 &&
                  EVP_EncryptUpdate(ectx, cipher.data(), &outl, kv.second.data(), 32) == 1 &&
                  EVP_EncryptFinal_ex(ectx, cipher.data() + outl, &finl) == 1 &&
                  EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
        EVP_CIPHER_CTX_free(ectx);
        if (!ok) throw std::runtime_error("backup encrypt failed");
        cipher.resize((size_t)outl + finl);
        s.WriteVarStr(std::vector<uint8_t>(kv.first.begin(), kv.first.end()));
        s.WriteVarStr(cipher);
        s.WriteVarStr(std::vector<uint8_t>(iv, iv + 12));
        s.WriteVarStr(std::vector<uint8_t>(tag, tag + 16));
        std::memset(kv.second.data(), 0, kv.second.size());
    }
    std::memset(kek, 0, 32);
    std::memset(salt.data(), 0, salt.size());
    return std::move(s.buf);
}

CWallet CWallet::Restore(const std::vector<uint8_t>& backup, const std::string& password,
                         std::string& error) {
    CWallet w;
    CDeserializer d(backup.data(), backup.size());
    uint8_t magic[4];
    if (!d.ReadBytes(magic, 4) || std::memcmp(magic, BACKUP_MAGIC, 4) != 0) {
        error = "invalid backup file";
        return w;
    }
    uint8_t ver;
    if (!d.ReadU8(ver) || ver != 1) {
        error = "unsupported backup version";
        return w;
    }
    std::vector<uint8_t> salt;
    if (!d.ReadVarStr(salt)) { error = "corrupt backup"; return w; }
    uint64_t n;
    if (!d.ReadVarInt(n) || n > 1000000) { error = "corrupt backup"; return w; }

    uint8_t kek[32];
    if (PKCS5_PBKDF2_HMAC(password.data(), (int)password.size(),
                          salt.data(), (int)salt.size(),
                          210000, EVP_sha256(), 32, kek) != 1) {
        error = "KDF failed";
        return w;
    }

    for (uint64_t i = 0; i < n; ++i) {
        std::vector<uint8_t> addrBytes, cipher, iv, tag;
        if (!d.ReadVarStr(addrBytes) || !d.ReadVarStr(cipher) || !d.ReadVarStr(iv) || !d.ReadVarStr(tag)) {
            error = "corrupt backup entry";
            std::memset(kek, 0, 32);
            return w;
        }
        EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
        std::vector<uint8_t> plain(cipher.size() + 16);
        int outl = 0, finl = 0;
        bool ok = EVP_DecryptInit_ex(ectx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                  EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
                  EVP_DecryptInit_ex(ectx, nullptr, nullptr, kek, iv.data()) == 1 &&
                  EVP_DecryptUpdate(ectx, plain.data(), &outl, cipher.data(), (int)cipher.size()) == 1 &&
                  EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data()) == 1 &&
                  EVP_DecryptFinal_ex(ectx, plain.data() + outl, &finl) == 1;
        EVP_CIPHER_CTX_free(ectx);
        if (!ok) {
            error = "wrong password or corrupt backup";
            std::memset(kek, 0, 32);
            return w;
        }
        plain.resize((size_t)outl + finl);
        if (plain.size() != 32) {
            error = "corrupt private key in backup";
            std::memset(kek, 0, 32);
            return w;
        }
        std::string addr(addrBytes.begin(), addrBytes.end());
        CKeyPair kp = CKeyPair::FromPrivKey(plain.data(), w.versionByte);
        std::memset(plain.data(), 0, plain.size());
        // ensure address matches stored address
        if (kp.IsValid() && kp.address == addr) {
            if (!w.keystore.Unlock(password)) {
                // unlock dengan salt baru; lalu add
                w.keystore.Unlock(password);
            }
            w.ImportKey(kp);
        }
    }
    std::memset(kek, 0, 32);
    w.keystore.Lock();
    return w;
}

} // namespace cdx
