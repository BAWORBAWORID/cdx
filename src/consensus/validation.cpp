#include "consensus/validation.h"
#include "consensus/rules.h"
#include "consensus/rewards.h"
#include "consensus/difficulty.h"
#include "script/interpreter.h"
#include "transaction/serializer.h"
#include "crypto/hash.h"
#include <cstring>
#include <ctime>
#include <openssl/evp.h>

namespace cdx {

bool CheckTransaction(const CTransaction& tx, std::string& error) {
    if (tx.vin.empty()) { error = "no inputs"; return false; }
    if (tx.vout.empty()) { error = "no outputs"; return false; }
    if (tx.vin.size() > MAX_TX_COUNT_PER_BLOCK) { error = "too many inputs"; return false; }
    if (tx.vout.size() > MAX_TX_COUNT_PER_BLOCK) { error = "too many outputs"; return false; }

    // cek duplicate inputs
    for (size_t i = 0; i < tx.vin.size(); ++i)
        for (size_t j = i + 1; j < tx.vin.size(); ++j)
            if (tx.vin[i].prevout == tx.vin[j].prevout) {
                error = "duplicate inputs";
                return false;
            }

    int64_t totalOut = 0;
    for (const auto& out : tx.vout) {
        if (out.value < 0) { error = "negative output"; return false; }
        if (out.value > MAX_MONEY) { error = "output exceeds max money"; return false; }
        totalOut += out.value;
        if (totalOut > MAX_MONEY) { error = "total output exceeds max money"; return false; }
    }

    if (tx.IsCoinBase()) {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100) {
            error = "coinbase scriptSig size invalid";
            return false;
        }
    } else {
        for (const auto& in : tx.vin) {
            if (in.prevout.hash.isZero()) { error = "null prevout in non-coinbase"; return false; }
        }
    }
    return true;
}

uint256 SignatureHash(const CTransaction& tx, size_t inputIndex,
                      const std::vector<uint8_t>& scriptPubKey) {
    CTransaction txCopy = tx;
    // kosongkan semua scriptSig
    for (auto& in : txCopy.vin) in.scriptSig.clear();
    // set scriptSig input ini menjadi scriptPubKey (bitcoin legacy sighash)
    txCopy.vin[inputIndex].scriptSig = scriptPubKey;
    // SIGHASH_ALL: tanda tangan atas semua output; append 0x01000000
    auto ser = SerializeTransaction(txCopy);
    uint8_t sighashAll[4] = {0x01, 0x00, 0x00, 0x00};
    uint8_t h[32];
    {
        // hash = SHA256d(ser || sighashAll)
        // gunakan EVP incremental via SHA256TwoParts? butuh double; lakukan manual
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        uint8_t first[32];
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, ser.data(), ser.size());
        EVP_DigestUpdate(ctx, sighashAll, 4);
        EVP_DigestFinal_ex(ctx, first, nullptr);
        EVP_MD_CTX_free(ctx);
        uint8_t second[32];
        SHA256(first, 32, second);
        std::memcpy(h, second, 32);
    }
    uint256 r;
    r.setBytesLE(h);
    return r;
}

bool CheckTxInputs(const CTransaction& tx,
                   const CCoinsView& view,
                   int64_t height,
                   int64_t& fee,
                   std::string& error) {
    if (tx.IsCoinBase()) {
        error = "coinbase has no inputs to check";
        return false;
    }
    int64_t inSum = 0, outSum = 0;
    for (const auto& in : tx.vin) {
        CUTXO coin;
        if (!view.GetCoin(in.prevout, coin)) {
            error = "input not found in UTXO set";
            return false;
        }
        if (!coin.IsSpendable(height)) {
            error = "coinbase input not mature";
            return false;
        }
        // verifikasi signature: sighash terhadap scriptPubKey output
        uint256 sh = SignatureHash(tx, (size_t)(&in - &tx.vin[0]), coin.scriptPubKey);
        uint8_t hash32[32];
        sh.getBytesLE(hash32);
        std::string verr;
        if (!VerifyScript(in.scriptSig, coin.scriptPubKey, hash32, verr)) {
            error = "signature verification failed: " + verr;
            return false;
        }
        inSum += coin.value;
        if (inSum > MAX_MONEY) { error = "input sum overflow"; return false; }
    }
    for (const auto& out : tx.vout) outSum += out.value;
    if (inSum < outSum) {
        error = "inputs < outputs";
        return false;
    }
    fee = inSum - outSum;
    return true;
}

bool ValidateTransaction(const CTransaction& tx,
                         const CCoinsView& view,
                         int64_t height,
                         int64_t& fee,
                         std::string& error,
                         bool checkCoinbase) {
    if (!CheckTransaction(tx, error)) return false;
    if (checkCoinbase && tx.IsCoinBase()) {
        // coinbase divalidasi di level block (subsidy)
        return true;
    }
    if (tx.IsCoinBase()) {
        error = "coinbase not allowed in mempool";
        return false;
    }
    return CheckTxInputs(tx, view, height, fee, error);
}

bool CheckBlockHeader(const CBlockHeader& hdr, const CBlockHeader* prev,
                      const ChainParams& params, std::string& error) {
    // PoW
    uint256 hash = hdr.GetHash();
    if (!CheckProofOfWork(hash, hdr.bits)) {
        error = "proof of work failed";
        return false;
    }
    // prev hash
    if (prev && hdr.prevBlockHash != prev->GetHash()) {
        error = "previous block hash mismatch";
        return false;
    }
    if (!prev) {
        // genesis: harus cocok dengan genesis hash network
        if (!params.genesisHashHex.empty()) {
            uint256 expected = uint256::fromHexReversed(params.genesisHashHex);
            if (hash != expected) {
                error = "genesis hash mismatch";
                return false;
            }
        }
    } else {
        // timestamp > prev timestamp
        if (hdr.timestamp <= prev->timestamp) {
            error = "timestamp not greater than prev";
            return false;
        }
    }
    return true;
}

bool CheckBlock(const CBlock& blk, int64_t height,
                const CCoinsView& view, const ChainParams& params,
                CCoinsView& viewOut, int64_t& fees, std::string& error) {
    fees = 0;
    viewOut = view; // salin state (validasi tidak memodifikasi view asli)

    // --- struktur ---
    if (blk.vtx.empty() || !blk.vtx[0].IsCoinBase()) {
        error = "first tx is not coinbase";
        return false;
    }
    // hanya satu coinbase
    for (size_t i = 1; i < blk.vtx.size(); ++i) {
        if (blk.vtx[i].IsCoinBase()) {
            error = "multiple coinbases";
            return false;
        }
    }
    if (blk.vtx.size() > MAX_TX_COUNT_PER_BLOCK) {
        error = "too many transactions";
        return false;
    }
    // merkle root
    if (!blk.CheckMerkleRoot()) {
        error = "merkle root mismatch";
        return false;
    }

    // --- pass 1: validasi & proses transaksi NON-coinbase ---
    // (akumulasi fee dulu; cek coinbase butuh total fee)
    for (size_t i = 1; i < blk.vtx.size(); ++i) {
        const auto& tx = blk.vtx[i];
        if (!CheckTransaction(tx, error)) return false;
        int64_t fee = 0;
        if (!CheckTxInputs(tx, viewOut, height, fee, error)) return false;
        fees += fee;
        // spend inputs
        for (const auto& in : tx.vin) {
            if (!viewOut.SpendCoin(in.prevout)) {
                error = "double spend";
                return false;
            }
        }
        // add outputs
        uint256 txid = GetTxID(tx);
        for (size_t j = 0; j < tx.vout.size(); ++j) {
            COutPoint out{txid, (uint32_t)j};
            CUTXO coin;
            coin.value = tx.vout[j].value;
            coin.scriptPubKey = tx.vout[j].scriptPubKey;
            coin.height = height;
            coin.isCoinbase = false;
            viewOut.AddCoin(out, coin);
        }
    }

    // --- pass 2: coinbase (subsidy + fees) ---
    {
        const auto& tx = blk.vtx[0];
        if (!CheckTransaction(tx, error)) return false;
        int64_t subsidy = GetBlockSubsidy(height);
        int64_t cbValue = 0;
        for (const auto& out : tx.vout) cbValue += out.value;
        if (!IsCoinbaseValueValid(cbValue, subsidy, fees)) {
            error = "coinbase value exceeds subsidy + fees";
            return false;
        }
        // coinbase output -> UTXO
        COutPoint out{GetTxID(tx), 0};
        CUTXO coin;
        coin.value = cbValue;
        coin.scriptPubKey = tx.vout[0].scriptPubKey;
        coin.height = height;
        coin.isCoinbase = true;
        viewOut.AddCoin(out, coin);
    }
    return true;
}

} // namespace cdx
