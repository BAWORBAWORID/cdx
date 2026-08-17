#include "rpc/methods.h"
#include "wallet/address.h"
#include "crypto/hash.h"
#include "crypto/encoding.h"
#include "transaction/serializer.h"
#include "script/interpreter.h"
#include "consensus/difficulty.h"
#include "consensus/policy.h"
#include "consensus/rewards.h"
#include "mining/pow.h"
#include <ctime>
#include <cstring>
#include <sstream>

namespace cdx {

static std::string JsonString(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            default: out += c;
        }
    }
    out += "\"";
    return out;
}

static std::string JsonInt(int64_t v) { return std::to_string(v); }

void RegisterRpcMethods(CRpcServer& server,
                        CBlockchain* blockchain,
                        CTxMemPool* mempool,
                        CWallet* wallet,
                        CMiner* miner,
                        CNetServer* net,
                        const ChainParams* params,
                        const std::function<bool(const CTransaction&)>& broadcastTx,
                        const std::function<void()>& requestMiningStop) {
    (void)requestMiningStop;

    server.Register("getblockchaininfo", [=](const std::vector<std::string>&) {
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        std::ostringstream o;
        o << "{\"chain\":" << JsonString(params->name)
          << ",\"blocks\":" << blockchain->GetHeight()
          << ",\"bestblockhash\":" << JsonString(blockchain->GetTipHash().getHex())
          << ",\"chainwork\":" << JsonString(blockchain->GetChainWork().getHex())
          << ",\"difficulty\":" << GetDifficultyFromBits(blockchain->GetTip() ? blockchain->GetTip()->bits : 0)
          << ",\"networkmagic\":" << params->networkMagic
          << ",\"size_on_disk\":0}";
        return o.str();
    });

    server.Register("getblockcount", [=](const std::vector<std::string>&) {
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        return JsonInt(blockchain->GetHeight());
    });

    server.Register("getblockhash", [=](const std::vector<std::string>& p) {
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        if (p.empty()) return std::string("null");
        int64_t h = std::atoll(p[0].c_str());
        CBlock blk;
        if (!blockchain->GetBlockByHeight(h, blk)) return std::string("null");
        return JsonString(blk.GetHash().getHex());
    });

    server.Register("getblock", [=](const std::vector<std::string>& p) {
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        if (p.empty()) return std::string("null");
        uint256 hash = uint256::fromHexReversed(p[0]);
        CBlock blk;
        if (!blockchain->GetBlock(hash, blk)) return std::string("null");
        std::ostringstream o;
        o << "{\"hash\":" << JsonString(hash.getHex())
          << ",\"height\":" << (blockchain->GetIndex(hash) ? blockchain->GetIndex(hash)->height : -1)
          << ",\"version\":" << blk.header.version
          << ",\"merkleroot\":" << JsonString(blk.header.merkleRoot.getHex())
          << ",\"time\":" << blk.header.timestamp
          << ",\"nonce\":" << blk.header.nonce
          << ",\"bits\":" << blk.header.bits
          << ",\"previousblockhash\":" << JsonString(blk.header.prevBlockHash.getHex())
          << ",\"tx\":[";
        for (size_t i = 0; i < blk.vtx.size(); ++i) {
            if (i) o << ",";
            o << JsonString(GetTxID(blk.vtx[i]).getHex());
        }
        o << "]}";
        return o.str();
    });

    server.Register("getrawtransaction", [=](const std::vector<std::string>& p) {
        if (p.empty()) return std::string("null");
        uint256 txid = uint256::fromHexReversed(p[0]);
        // cari di mempool dulu
        {
            std::lock_guard<std::mutex> lk(blockchain->GetMutex());
            auto it = mempool->mapTx.find(txid);
            if (it != mempool->mapTx.end()) {
                return JsonString(toHex(SerializeTransaction(it->second.tx)));
            }
        }
        // cari di blockchain (scan per block; chain kecil — cukup)
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        for (int64_t h = 0; h <= blockchain->GetHeight(); ++h) {
            CBlock blk;
            if (!blockchain->GetBlockByHeight(h, blk)) continue;
            for (const auto& tx : blk.vtx) {
                if (GetTxID(tx) == txid)
                    return JsonString(toHex(SerializeTransaction(tx)));
            }
        }
        return std::string("null");
    });

    // listunspent <address> — scan UTXO set untuk alamat tertentu
    server.Register("listunspent", [=](const std::vector<std::string>& p) {
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        if (p.empty()) return std::string("[]");
        uint8_t ver, hash160[20];
        if (!DecodeAddress(p[0], ver, hash160)) return std::string("[]");
        int64_t height = blockchain->GetHeight();
        const auto& view = blockchain->GetView();
        std::ostringstream o;
        o << "[";
        bool first = true;
        for (const auto& kv : view.utxo) {
            uint8_t h[20];
            if (!ExtractP2PKHHash(kv.second.scriptPubKey, h)) continue;
            if (std::memcmp(h, hash160, 20) != 0) continue;
            if (!first) o << ",";
            first = false;
            o << "{\"txid\":" << JsonString(kv.first.hash.getHex())
              << ",\"vout\":" << kv.first.n
              << ",\"value\":" << kv.second.value
              << ",\"height\":" << kv.second.height
              << ",\"coinbase\":" << (kv.second.isCoinbase ? "true" : "false")
              << ",\"spendable\":" << (kv.second.IsSpendable(height) ? "true" : "false") << "}";
        }
        o << "]";
        return o.str();
    });

    // getaddresstxs <address> — scan chain, list tx yang menyentuh alamat
    server.Register("getaddresstxs", [=](const std::vector<std::string>& p) {
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        if (p.empty()) return std::string("[]");
        uint8_t ver, hash160[20];
        if (!DecodeAddress(p[0], ver, hash160)) return std::string("[]");
        auto target = BuildP2PKHScript(hash160);
        auto touches = [&](const CTransaction& tx) -> bool {
            for (const auto& out : tx.vout)
                if (out.scriptPubKey == target) return true;
            for (const auto& in : tx.vin) {
                std::vector<uint8_t> pub;
                GetScriptSigPubKey(in.scriptSig, pub);
                if (pub.empty()) continue;
                uint8_t hh[20];
                HASH160(pub.data(), pub.size(), hh);
                if (std::memcmp(hh, hash160, 20) == 0) return true;
            }
            return false;
        };
        std::ostringstream o;
        o << "[";
        bool first = true;
        for (int64_t h = 0; h <= blockchain->GetHeight(); ++h) {
            CBlock blk;
            if (!blockchain->GetBlockByHeight(h, blk)) continue;
            for (const auto& tx : blk.vtx) {
                if (!touches(tx)) continue;
                if (!first) o << ",";
                first = false;
                o << "{\"txid\":" << JsonString(GetTxID(tx).getHex())
                  << ",\"height\":" << h
                  << ",\"blockhash\":" << JsonString(blk.GetHash().getHex())
                  << ",\"iscoinbase\":" << (tx.IsCoinBase() ? "true" : "false") << "}";
            }
        }
        // mempool (belum dikonfirmasi)
        for (const auto& kv : mempool->mapTx) {
            const auto& tx = kv.second.tx;
            if (!touches(tx)) continue;
            if (!first) o << ",";
            first = false;
            o << "{\"txid\":" << JsonString(kv.first.getHex())
              << ",\"height\":-1"
              << ",\"blockhash\":\"\""
              << ",\"iscoinbase\":false}";
        }
        o << "]";
        return o.str();
    });

    server.Register("sendrawtransaction", [=](const std::vector<std::string>& p) {
        if (p.empty()) return std::string("\"error: missing hex\"");
        std::vector<uint8_t> bytes;
        if (!DecodeHex(p[0], bytes)) return std::string("\"error: invalid hex\"");
        CTransaction tx;
        if (!DeserializeTransaction(bytes.data(), bytes.size(), tx))
            return std::string("\"error: invalid transaction\"");
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        int64_t fee = 0;
        std::string error;
        int64_t height = blockchain->GetHeight();
        if (!mempool->CheckTx(tx, blockchain->GetView(), height, fee, error))
            return std::string("\"error: " + error + "\"");
        mempool->AddUnchecked(tx, fee, height, (int64_t)time(nullptr));
        if (broadcastTx) broadcastTx(tx);
        return JsonString(GetTxID(tx).getHex());
    });

    server.Register("getbalance", [=](const std::vector<std::string>&) {
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        if (!wallet) return std::string("0");
        auto bal = wallet->GetBalance(blockchain->GetView(), blockchain->GetHeight());
        std::ostringstream o;
        o << "{\"confirmed\":" << bal.confirmed
          << ",\"unconfirmed\":" << bal.unconfirmed
          << ",\"immature\":" << bal.immature
          << ",\"spendable\":" << bal.spendable << "}";
        return o.str();
    });

    server.Register("getnewaddress", [=](const std::vector<std::string>&) {
        if (!wallet) return std::string("null");
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        CKeyPair kp = wallet->GenerateNewAddress();
        return JsonString(kp.address);
    });

    server.Register("listtransactions", [=](const std::vector<std::string>&) {
        if (!wallet) return std::string("[]");
        auto hist = wallet->GetHistory();
        std::ostringstream o;
        o << "[";
        for (size_t i = 0; i < hist.size(); ++i) {
            if (i) o << ",";
            o << "{\"txid\":" << JsonString(hist[i].txid.getHex())
              << ",\"height\":" << hist[i].height
              << ",\"amount\":" << hist[i].amount
              << ",\"fee\":" << hist[i].fee
              << ",\"address\":" << JsonString(hist[i].address)
              << ",\"category\":" << (hist[i].amount >= 0 ? JsonString("receive") : JsonString("send")) << "}";
        }
        o << "]";
        return o.str();
    });

    server.Register("getnetworkinfo", [=](const std::vector<std::string>&) {
        std::ostringstream o;
        o << "{\"version\":\"0.1.0\",\"subversion\":\"/CDX:0.1.0/\","
          << "\"protocolversion\":" << PROTOCOL_VERSION
          << ",\"connections\":" << (net ? (int64_t)net->GetPeerCount() : 0)
          << ",\"networkactive\":true}";
        return o.str();
    });

    server.Register("getpeerinfo", [=](const std::vector<std::string>&) {
        std::ostringstream o;
        o << "[";
        if (net) {
            auto peers = net->GetPeerList();
            for (size_t i = 0; i < peers.size(); ++i) {
                if (i) o << ",";
                o << "{\"addr\":" << JsonString(peers[i].first)
                  << ",\"handshake\":" << (peers[i].second ? "true" : "false") << "}";
            }
        }
        o << "]";
        return o.str();
    });

    server.Register("getmininginfo", [=](const std::vector<std::string>&) {
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        std::ostringstream o;
        o << "{\"blocks\":" << blockchain->GetHeight()
          << ",\"difficulty\":" << (blockchain->GetTip() ? GetDifficultyFromBits(blockchain->GetTip()->bits) : 0)
          << ",\"networkhashps\":0";
        if (miner) {
            auto st = miner->GetStatus();
            o << ",\"mining\":" << (st.mining ? "true" : "false")
              << ",\"miningaddress\":" << JsonString(st.miningAddress)
              << ",\"blocksfound\":" << st.blocksFound
              << ",\"immaturereward\":" << st.immatureReward
              << ",\"maturedreward\":" << st.maturedReward;
        }
        o << "}";
        return o.str();
    });

    server.Register("getmempoolinfo", [=](const std::vector<std::string>&) {
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        std::ostringstream o;
        o << "{\"size\":" << mempool->Size()
          << ",\"bytes\":0,\"fees\":" << mempool->GetTotalFees() << "}";
        return o.str();
    });

    server.Register("validateaddress", [=](const std::vector<std::string>& p) {
        if (p.empty()) return std::string("{\"isvalid\":false}");
        bool valid = IsValidAddress(p[0]);
        std::ostringstream o;
        o << "{\"isvalid\":" << (valid ? "true" : "false")
          << ",\"address\":" << JsonString(p[0]) << "}";
        return o.str();
    });

    server.Register("estimatesmartfee", [=](const std::vector<std::string>&) {
        std::ostringstream o;
        o << "{\"feerate\":" << (double)EstimateSmartFee() / 100000000.0
          << ",\"blocks\":6}";
        return o.str();
    });

    server.Register("getblockheader", [=](const std::vector<std::string>& p) {
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        if (p.empty()) return std::string("null");
        uint256 hash = uint256::fromHexReversed(p[0]);
        CBlockHeader hdr;
        if (!blockchain->GetBlockHeader(hash, hdr)) return std::string("null");
        std::ostringstream o;
        o << "{\"hash\":" << JsonString(hash.getHex())
          << ",\"confirmations\":" << (blockchain->GetHeight() - (blockchain->GetIndex(hash) ? blockchain->GetIndex(hash)->height : 0) + 1)
          << ",\"height\":" << (blockchain->GetIndex(hash) ? blockchain->GetIndex(hash)->height : -1)
          << ",\"version\":" << hdr.version
          << ",\"merkleroot\":" << JsonString(hdr.merkleRoot.getHex())
          << ",\"time\":" << hdr.timestamp
          << ",\"nonce\":" << hdr.nonce
          << ",\"bits\":" << hdr.bits
          << ",\"previousblockhash\":" << JsonString(hdr.prevBlockHash.getHex()) << "}";
        return o.str();
    });

    server.Register("gettxoutsetinfo", [=](const std::vector<std::string>&) {
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        const auto& view = blockchain->GetView();
        std::ostringstream o;
        o << "{\"height\":" << blockchain->GetHeight()
          << ",\"transactions\":" << view.Size()
          << ",\"total_amount\":" << view.TotalValue() << "}";
        return o.str();
    });

    server.Register("gettxout", [=](const std::vector<std::string>& p) {
        std::lock_guard<std::mutex> lk(blockchain->GetMutex());
        if (p.size() < 2) return std::string("null");
        uint256 txid = uint256::fromHexReversed(p[0]);
        uint32_t n = (uint32_t)std::atoll(p[1].c_str());
        COutPoint out{txid, n};
        CUTXO coin;
        if (!blockchain->GetView().GetCoin(out, coin)) return std::string("null");
        std::ostringstream o;
        o << "{\"value\":" << coin.value
          << ",\"height\":" << coin.height
          << ",\"coinbase\":" << (coin.isCoinbase ? "true" : "false") << "}";
        return o.str();
    });
}

} // namespace cdx
