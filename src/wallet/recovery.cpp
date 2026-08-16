#include "wallet/recovery.h"
#include "wallet/address.h"
#include "script/interpreter.h"
#include "transaction/serializer.h"

namespace cdx {

int64_t WalletRescan(CWallet& wallet, CBlockchain& blockchain, std::string& error) {
    (void)error;
    int64_t found = 0;
    // bangun set hash160 milik wallet
    std::vector<uint8_t> ownHashes;
    std::vector<std::string> addrs = wallet.GetAddresses();
    for (const auto& a : addrs) {
        uint8_t v, h[20];
        if (DecodeAddress(a, v, h)) {
            ownHashes.insert(ownHashes.end(), h, h + 20);
        }
    }
    auto isOwn = [&](const std::vector<uint8_t>& script) {
        uint8_t h[20];
        if (!ExtractP2PKHHash(script, h)) return false;
        for (size_t i = 0; i + 20 <= ownHashes.size(); i += 20) {
            if (std::memcmp(ownHashes.data() + i, h, 20) == 0) return true;
        }
        return false;
    };

    int64_t height = blockchain.GetHeight();
    for (int64_t h = 0; h <= height; ++h) {
        CBlock blk;
        if (!blockchain.GetBlockByHeight(h, blk)) continue;
        for (const auto& tx : blk.vtx) {
            bool relevant = false;
            int64_t amount = 0;
            std::string counterparty;
            for (const auto& in : tx.vin) {
                if (in.prevout.hash.isZero()) continue;
                // check spent output milik wallet (butuh akses UTXO history — 
                // untuk kesederhanaan, catat via view sekarang)
            }
            for (const auto& out : tx.vout) {
                if (isOwn(out.scriptPubKey)) {
                    relevant = true;
                    amount += out.value;
                }
            }
            if (!relevant) continue;
            WalletTxRecord rec;
            rec.txid = GetTxID(tx);
            rec.height = h;
            rec.amount = amount;
            rec.fee = 0;
            rec.isCoinbase = tx.IsCoinBase();
            rec.timestamp = blk.header.timestamp;
            wallet.AddRecord(rec);
            ++found;
        }
    }
    return found;
}

} // namespace cdx
