#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace cdx {

// ---------------------------------------------------------------------------
// secp256k1 keypair + ECDSA signature (RFC6979 deterministic).
// Menggunakan OpenSSL sebagai library established — tidak ada custom crypto.
// ---------------------------------------------------------------------------

constexpr size_t PRIVKEY_SIZE = 32;
constexpr size_t PUBKEY_COMPRESSED_SIZE = 33;
constexpr size_t PUBKEY_UNCOMPRESSED_SIZE = 65;
constexpr size_t SIGNATURE_DER_MAX_SIZE = 72;

class CKey {
public:
    CKey();
    ~CKey();
    CKey(const CKey& other);
    CKey& operator=(const CKey& other);
    CKey(CKey&& other) noexcept;
    CKey& operator=(CKey&& other) noexcept;

    // generate keypair baru dari secure random (crypto.randomBytes equivalent)
    static CKey Generate();

    // load dari byte privat key (32 byte); validasi range < n
    bool SetPrivKey(const uint8_t* p, size_t len);

    bool IsValid() const;
    bool IsCompressed() const { return fCompressed; }
    void SetCompressed(bool c) { fCompressed = c; }

    // 32-byte private key
    void GetPrivKey(uint8_t out[32]) const;

    // public key terkompresi 33 byte (0x02/0x03 || x)
    bool GetPubKeyCompressed(uint8_t out[33]) const;
    // public key uncompressed 65 byte (0x04 || x || y)
    bool GetPubKeyUncompressed(uint8_t out[65]) const;

    // tanda tangan ECDSA deterministic RFC6979 (DER encoded)
    bool Sign(const uint8_t* hash32, size_t len, uint8_t* out, size_t& outlen) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
    bool fCompressed = true;
    bool fValid = false;
};

// verifikasi signature (DER) terhadap hash 32-byte dan public key
bool VerifySignature(const uint8_t* hash32, size_t len,
                     const uint8_t* sig, size_t siglen,
                     const uint8_t* pubkey, size_t pubkeylen);

// konversi pubkey: 33 -> 65 dan sebaliknya
bool CompressPubKey(const uint8_t* pubkey65, size_t len, uint8_t out33[33]);
bool DecompressPubKey(const uint8_t* pubkey33, size_t len, uint8_t out65[65]);

} // namespace cdx
