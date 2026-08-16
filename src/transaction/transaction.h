#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include "crypto/uint256.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Transaction model — UTXO model bitcoin-style.
// Semua nilai moneter dalam base units (int64_t), tidak ada floating point.
// ---------------------------------------------------------------------------

// OutPoint: referensi ke output transaksi sebelumnya
struct COutPoint {
    uint256 hash;   // txid (SHA256d serialized tx)
    uint32_t n = 0; // index output

    bool operator==(const COutPoint& o) const { return hash == o.hash && n == o.n; }
    bool operator!=(const COutPoint& o) const { return !(*this == o); }
    bool operator<(const COutPoint& o) const {
        if (hash != o.hash) return hash < o.hash;
        return n < o.n;
    }
};

// Input transaksi
struct CTxIn {
    COutPoint prevout;
    std::vector<uint8_t> scriptSig;
    uint32_t sequence = 0xffffffff;

    bool operator==(const CTxIn& o) const {
        return prevout == o.prevout && scriptSig == o.scriptSig && sequence == o.sequence;
    }
};

// Output transaksi
struct CTxOut {
    int64_t value = 0; // base units (1 CDX = 100_000_000)
    std::vector<uint8_t> scriptPubKey;

    bool operator==(const CTxOut& o) const {
        return value == o.value && scriptPubKey == o.scriptPubKey;
    }
};

// Transaksi
struct CTransaction {
    int32_t version = 1;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t lockTime = 0;

    bool IsCoinBase() const {
        return vin.size() == 1 && vin[0].prevout.hash.isZero() && vin[0].prevout.n == 0xffffffff;
    }

    bool operator==(const CTransaction& o) const {
        return version == o.version && vin == o.vin && vout == o.vout && lockTime == o.lockTime;
    }
};

// helper: format nilai dalam CDX (desimal 8 digit)
std::string FormatValue(int64_t baseUnits);
// parse string nilai CDX -> base units; melempar pada input invalid
int64_t ParseValue(const std::string& s);

} // namespace cdx
