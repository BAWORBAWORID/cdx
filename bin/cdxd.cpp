#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>
#include <iostream>
#include <memory>
#include <functional>
#include <fstream>
#include <csignal>
#include <execinfo.h>
#include <unistd.h>
#include <filesystem>

#include "config/networks.h"
#include "storage/blocks.h"
#include "blockchain/blockchain.h"
#include "blockchain/reorg.h"
#include "blockchain/genesis.h"
#include "consensus/validation.h"
#include "consensus/difficulty.h"
#include "consensus/rewards.h"
#include "mempool/mempool.h"
#include "wallet/wallet.h"
#include "wallet/backup.h"
#include "wallet/recovery.h"
#include "mining/miner.h"
#include "mining/pow.h"
#include "blockchain/merkle.h"
#include "p2p/server.h"
#include "p2p/sync.h"
#include "rpc/server.h"
#include "rpc/methods.h"
#include "transaction/serializer.h"
#include "crypto/hash.h"
#include "crypto/encoding.h"

using namespace cdx;

// ---------------------------------------------------------------------------
// Node CDX — full node.
//   - blockchain + UTXO (source of truth)
//   - mempool
//   - wallet (non-HD, encrypted)
//   - miner (opsional)
//   - P2P (relay + sync)
//   - RPC (localhost, authenticated)
// ---------------------------------------------------------------------------

static std::atomic<bool> g_stop{false};

// handler sinyal: cetak backtrace lalu exit
static void CrashHandler(int sig) {
    void* frames[64];
    int n = backtrace(frames, 64);
    std::fprintf(stderr, "\n=== CDX CRASH: signal %d ===\n", sig);
    backtrace_symbols_fd(frames, n, 2);
    _exit(1);
}

static void InstallCrashHandlers() {
    std::signal(SIGSEGV, CrashHandler);
    std::signal(SIGABRT, CrashHandler);
    std::signal(SIGBUS, CrashHandler);
    std::signal(SIGILL, CrashHandler);
}

struct NodeOptions {
    std::string network = "mainnet";
    std::string dataDir = "data";
    std::string rpcUser = "cdx";
    std::string rpcPassword = "cdx";
    uint16_t port = 0;   // 0 = default network port
    uint16_t rpcPort = 0; // 0 = default network rpc port
    bool disableMining = true;
    bool disableNetwork = false;
    std::vector<std::string> connect;
    std::vector<std::string> addnode;
    std::string walletPassword = "cdx";
    bool generate = false; // regtest: mine terus-menerus
    int64_t generateBlocks = 0; // regtest: mine N block lalu stop
    std::string miningAddress;
    bool rescan = false;
};

static void PrintUsage() {
    std::printf(
        "CDX Full Node — Codex Coin\n"
        "Usage: cdxd [options]\n"
        "  -network=<mainnet|testnet|regtest>   chain selection\n"
        "  -datadir=<path>                      data directory (default: data)\n"
        "  -rpcuser=<user>  -rpcpassword=<pass> RPC credentials\n"
        "  -connect=<host:port>                 connect to specific peer\n"
        "  -addnode=<host:port>                 add node and connect\n"
        "  -mining                             enable mining\n"
        "  -miningaddress=<addr>                miner payout address\n"
        "  -walletpassword=<pass>               wallet encryption password\n"
        "  -generate                            mine continuously (regtest)\n"
        "  -generate=<n>                        mine n blocks then stop\n"
        "  -rescan                              rescan wallet after load\n"
        "  -dnsseed                            enable DNS seed resolution (default on)\n");
}

static NodeOptions ParseArgs(int argc, char** argv) {
    NodeOptions o;
    bool mining = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto val = [&](const std::string& key) -> std::string {
            std::string pref = "-" + key + "=";
            if (a.rfind(pref, 0) == 0) return a.substr(pref.size());
            return "";
        };
        if (a == "-h" || a == "-help" || a == "--help") { PrintUsage(); exit(0); }
        if (!val("network").empty()) o.network = val("network");
        else if (!val("datadir").empty()) o.dataDir = val("datadir");
        else if (!val("rpcuser").empty()) o.rpcUser = val("rpcuser");
        else if (!val("rpcpassword").empty()) o.rpcPassword = val("rpcpassword");
        else if (!val("port").empty()) o.port = (uint16_t)std::atoi(val("port").c_str());
        else if (!val("rpcport").empty()) o.rpcPort = (uint16_t)std::atoi(val("rpcport").c_str());
        else if (!val("connect").empty()) o.connect.push_back(val("connect"));
        else if (!val("addnode").empty()) o.addnode.push_back(val("addnode"));
        else if (!val("walletpassword").empty()) o.walletPassword = val("walletpassword");
        else if (!val("miningaddress").empty()) { o.miningAddress = val("miningaddress"); mining = true; }
        else if (!val("generate").empty()) {
            o.generate = true;
            o.generateBlocks = std::atoll(val("generate").c_str());
            mining = true;
        }
        else if (a == "-mining") { mining = true; }
        else if (a == "-generate") { o.generate = true; mining = true; }
        else if (a == "-rescan") { o.rescan = true; }
        else if (a == "-dnsseed=0") { /* accepted, seed resolution optional */ }
        else if (a == "-h") { PrintUsage(); exit(0); }
        else {
            std::printf("unknown option: %s\n", a.c_str());
            PrintUsage();
            exit(1);
        }
    }
    o.disableMining = !mining;
    return o;
}

// ---------------------------------------------------------------------------
// Node handler — integrasi P2P messages
// ---------------------------------------------------------------------------
class CNodeHandler : public INodeHandler {
public:
    CNodeHandler(CBlockchain& chain, CTxMemPool& mempool, CNetServer& net,
                 CWallet* wallet, CMiner* miner, const NodeOptions& opts)
        : chain(chain), mempool(mempool), net(net), wallet(wallet), miner(miner), opts(opts) {}

    void OnMessage(CNode& node, const CNetMessage& msg) override;
    void OnDisconnect(CNode& node) override { (void)node; }

private:
    CBlockchain& chain;
    CTxMemPool& mempool;
    CNetServer& net;
    CWallet* wallet;
    CMiner* miner;
    const NodeOptions& opts;

    void HandleVersion(CNode& node, const std::vector<uint8_t>& payload);
    void HandleInv(CNode& node, const std::vector<uint8_t>& payload);
    void HandleGetData(CNode& node, const std::vector<uint8_t>& payload);
    void HandleTx(CNode& node, const std::vector<uint8_t>& payload);
    void HandleBlock(CNode& node, const std::vector<uint8_t>& payload);
    void HandleGetHeaders(CNode& node, const std::vector<uint8_t>& payload);
    void HandleHeaders(CNode& node, const std::vector<uint8_t>& payload);
    void HandlePing(CNode& node, const std::vector<uint8_t>& payload);

    // broadcast transaksi ke semua peer
    void RelayTx(const CTransaction& tx);
};

void CNodeHandler::HandleVersion(CNode& node, const std::vector<uint8_t>& payload) {
    CVersionMessage v;
    if (!DeserializeVersion(payload, v)) {
        node.MarkDisconnected();
        return;
    }
    if (v.version < MIN_PROTOCOL_VERSION) {
        node.MarkDisconnected();
        return;
    }
    node.theirVersion = v;
    node.handshakeDone = true;
    // kirim version balasan (jika inbound) + verack
    if (node.inbound) {
        CVersionMessage mine;
        mine.startHeight = (int32_t)chain.GetHeight();
        auto ser = SerializeVersion(mine);
        net.SendTo(node.fd, "version", ser);
    }
    net.SendTo(node.fd, "verack", {});
    // minta headers untuk sync
    {
        std::vector<uint256> locator;
        std::lock_guard<std::mutex> lk(chain.GetMutex());
        if (chain.GetHeight() >= 0) {
            for (int64_t h = chain.GetHeight(); h >= 0 && locator.size() < 32; h -= (locator.size() > 10 ? 2 : 1)) {
                uint256 hh;
                if (chain.GetBlockHashByHeight(h, hh)) locator.push_back(hh);
            }
        }
        auto payload = BuildGetHeadersPayload(locator, uint256());
        net.SendTo(node.fd, "getheaders", payload);
    }
}

void CNodeHandler::HandleInv(CNode& node, const std::vector<uint8_t>& payload) {
    std::vector<CInv> inv;
    if (!DeserializeInv(payload, inv)) {
        node.misbehaviorScore += 10;
        return;
    }
    // minta data yang belum kita punya
    std::vector<CInv> want;
    {
        std::lock_guard<std::mutex> lk(chain.GetMutex());
        for (const auto& i : inv) {
            if (i.type == InvType::TX) {
                if (!mempool.Exists(i.hash)) want.push_back(i);
            } else if (i.type == InvType::BLOCK) {
                if (!chain.HaveBlock(i.hash)) want.push_back(i);
            }
            if (want.size() >= 500) break;
        }
    }
    if (!want.empty()) {
        auto ser = SerializeInv(want);
        net.SendTo(node.fd, "getdata", ser);
    }
}

void CNodeHandler::HandleGetData(CNode& node, const std::vector<uint8_t>& payload) {
    std::vector<CInv> inv;
    if (!DeserializeInv(payload, inv)) {
        node.misbehaviorScore += 10;
        return;
    }
    // kumpulkan data di bawah lock, kirim SETELAH lock dilepas
    // (mengirim sambil memegang chain mutex bisa memblokir mining/RPC).
    std::vector<std::vector<uint8_t>> txSer;
    std::vector<std::vector<uint8_t>> blockSer;
    {
        std::lock_guard<std::mutex> lk(chain.GetMutex());
        for (const auto& i : inv) {
            if (i.type == InvType::TX) {
                auto it = mempool.mapTx.find(i.hash);
                if (it != mempool.mapTx.end()) txSer.push_back(SerializeTransaction(it->second.tx));
            } else if (i.type == InvType::BLOCK) {
                CBlock blk;
                if (chain.GetBlock(i.hash, blk)) blockSer.push_back(SerializeBlock(blk));
            }
        }
    }
    for (const auto& ser : txSer) net.SendTo(node.fd, "tx", ser);
    for (const auto& ser : blockSer) net.SendTo(node.fd, "block", ser);
}

void CNodeHandler::HandleTx(CNode& node, const std::vector<uint8_t>& payload) {
    CTransaction tx;
    if (!ParseTxPayload(payload, tx)) {
        node.misbehaviorScore += 10;
        return;
    }
    std::lock_guard<std::mutex> lk(chain.GetMutex());
    uint256 txid = GetTxID(tx);
    if (mempool.Exists(txid)) return;
    int64_t fee = 0;
    std::string error;
    int64_t height = chain.GetHeight();
    if (!mempool.CheckTx(tx, chain.GetView(), height, fee, error)) {
        node.misbehaviorScore += 5;
        return;
    }
    mempool.AddUnchecked(tx, fee, height, (int64_t)time(nullptr));
    // relay
    RelayTx(tx);
}

void CNodeHandler::HandleBlock(CNode& node, const std::vector<uint8_t>& payload) {
    CBlock blk;
    if (!ParseBlockPayload(payload, blk)) {
        node.misbehaviorScore += 10;
        return;
    }
    std::lock_guard<std::mutex> lk(chain.GetMutex());
    uint256 hash = blk.GetHash();
    if (chain.HaveBlock(hash)) return;
    ReorgResult r = TryAcceptBlock(chain, blk, mempool);
    if (r.ok) {
        // clean mempool terhadap UTXO baru
        std::vector<uint256> removed;
        mempool.RemoveSpent(chain.GetView(), chain.GetHeight(), removed);
        // relay block
        net.BroadcastMessage("inv", SerializeInv({{InvType::BLOCK, hash}}), node.fd);
        // update wallet history
        if (wallet) {
            const CBlockIndex* idx = chain.GetIndex(hash);
            if (idx) {
                for (const auto& tx : blk.vtx) {
                    WalletTxRecord rec;
                    rec.txid = GetTxID(tx);
                    rec.height = idx->height;
                    rec.isCoinbase = tx.IsCoinBase();
                    rec.timestamp = blk.header.timestamp;
                    // amount dihitung saat rescan; di sini catat minimal
                    wallet->AddRecord(rec);
                }
            }
        }
    } else if (r.error.find("unknown prev") != std::string::npos) {
        // block datang lebih cepat dari sync kita (broadcast saat masih
        // mengejar chain): jangan hukum peer — minta headers lagi untuk
        // resume sinkronisasi (Bitcoin-style: request lebih banyak headers).
        // catatan: HandleBlock sudah memegang chain mutex di sini
        std::vector<uint256> locator;
        for (int64_t hh = chain.GetHeight(); hh >= 0 && locator.size() < 32;
             hh -= (locator.size() > 10 ? 2 : 1)) {
            uint256 hh2;
            if (chain.GetBlockHashByHeight(hh, hh2)) locator.push_back(hh2);
        }
        auto p = BuildGetHeadersPayload(locator, uint256());
        net.SendTo(node.fd, "getheaders", p);
    } else if (!r.error.empty()) {
        node.misbehaviorScore += 10;
    }
}

void CNodeHandler::HandleGetHeaders(CNode& node, const std::vector<uint8_t>& payload) {
    std::vector<uint256> locator;
    uint256 hashStop;
    if (!ParseGetHeadersPayload(payload, locator, hashStop)) {
        node.misbehaviorScore += 10;
        return;
    }
    std::vector<uint8_t> ser;
    {
        std::lock_guard<std::mutex> lk(chain.GetMutex());
        // mulai dari locator terbaru yang kita punya (untuk resume sync)
        int64_t startHeight = 0;
        for (const auto& h : locator) {
            const CBlockIndex* idx = chain.GetIndex(h);
            if (idx) {
                startHeight = idx->height + 1;
                break;
            }
        }
        std::vector<CBlockHeader> out;
        for (int64_t h = startHeight; h <= chain.GetHeight() && out.size() < 2000; ++h) {
            CBlock blk;
            if (!chain.GetBlockByHeight(h, blk)) break;
            out.push_back(blk.header);
            if (!hashStop.isZero() && blk.GetHash() == hashStop) break;
        }
        ser = BuildHeadersPayload(out);
    }
    net.SendTo(node.fd, "headers", ser);
}

void CNodeHandler::HandleHeaders(CNode& node, const std::vector<uint8_t>& payload) {
    std::vector<CBlockHeader> headers;
    if (!ParseHeadersPayload(payload, headers)) {
        node.misbehaviorScore += 10;
        return;
    }
    if (headers.empty()) return;
    // minta block yang belum kita punya — dalam BATCH terbatas agar
    // download tetap ter-pace mengikuti kecepatan proses lokal
    // (socket peer tidak dibanjiri; Bitcoin-style download window).
    std::vector<CInv> want;
    bool haveAll = true;
    {
        std::lock_guard<std::mutex> lk(chain.GetMutex());
        size_t n = 0;
        for (const auto& h : headers) {
            uint256 hash = h.GetHash();
            if (!chain.HaveBlock(hash)) {
                haveAll = false;
                if (n < 100) { want.push_back({InvType::BLOCK, hash}); ++n; }
            }
        }
    }
    if (!want.empty()) {
        net.SendTo(node.fd, "getdata", SerializeInv(want));
    }
    // minta lanjutan headers jika batch penuh atau masih ada yang belum
    // kita punya — locator berbasis tip kita, jadi A menjawab dari tip+1.
    if (!haveAll || headers.size() >= 2000) {
        std::vector<uint256> locator;
        {
            std::lock_guard<std::mutex> lk(chain.GetMutex());
            for (int64_t h = chain.GetHeight(); h >= 0 && locator.size() < 32;
                 h -= (locator.size() > 10 ? 2 : 1)) {
                uint256 hh;
                if (chain.GetBlockHashByHeight(h, hh)) locator.push_back(hh);
            }
        }
        auto p = BuildGetHeadersPayload(locator, uint256());
        net.SendTo(node.fd, "getheaders", p);
    }
}

void CNodeHandler::HandlePing(CNode& node, const std::vector<uint8_t>& payload) {
    // pong dengan payload sama
    net.SendTo(node.fd, "pong", payload);
}

void CNodeHandler::RelayTx(const CTransaction& tx) {
    auto ser = SerializeTransaction(tx);
    net.BroadcastMessage("tx", ser);
}

void CNodeHandler::OnMessage(CNode& node, const CNetMessage& msg) {
    if (msg.command == "version") HandleVersion(node, msg.payload);
    else if (msg.command == "verack") { node.verackReceived = true; }
    else if (msg.command == "inv") HandleInv(node, msg.payload);
    else if (msg.command == "getdata") HandleGetData(node, msg.payload);
    else if (msg.command == "tx") HandleTx(node, msg.payload);
    else if (msg.command == "block") HandleBlock(node, msg.payload);
    else if (msg.command == "getheaders") HandleGetHeaders(node, msg.payload);
    else if (msg.command == "headers") HandleHeaders(node, msg.payload);
    else if (msg.command == "ping") HandlePing(node, msg.payload);
    else if (msg.command == "pong") { node.lastPingTime = (int64_t)time(nullptr); }
    else if (msg.command == "getaddr") {
        // kirim addr peers yang kita kenal
        auto peers = net.GetPeerList();
        std::vector<uint8_t> payload;
        CSerializer s;
        s.WriteVarInt(peers.size());
        for (const auto& p : peers) {
            // addr payload: time(4) + services(8) + ip(16) + port(2)
            // parse host:port sederhana — pakai ip 0.0.0.0 untuk placeholder
            uint8_t addr[26] = {0};
            s.WriteBytes(addr, 26);
        }
        net.SendTo(node.fd, "addr", s.buf);
    }
    else if (msg.command == "addr") {
        // simpan peer addresses (discovery)
    }
}

// ---------------------------------------------------------------------------
// Miner loop
// ---------------------------------------------------------------------------
static void RunMinerLoop(CBlockchain& chain, CTxMemPool& mempool, CMiner& miner,
                         CNetServer& net, const NodeOptions& opts, const ChainParams& params,
                         std::atomic<bool>& stop);

// Mining thread lifecycle: dapat dimulai dari startup (-mining/-generate)
// maupun dari RPC (startmining/stopmining).
static std::mutex g_minerMutex;
static std::thread g_minerThread;
static std::atomic<bool> g_minerThreadActive{false};

static void StartMiningThread(CBlockchain& blockchain, CTxMemPool& mempool, CMiner& miner,
                              CNetServer& net, const NodeOptions& opts, const ChainParams& params,
                              std::atomic<bool>& stop) {
    std::lock_guard<std::mutex> lk(g_minerMutex);
    if (g_minerThreadActive.load()) return;
    // set flag sinkron (jangan andalkan thread RunLoop yang asinkron)
    miner.stopRequested = false;
    miner.running = true;
    g_minerThreadActive = true;
    g_minerThread = std::thread([&]() {
        RunMinerLoop(blockchain, mempool, miner, net, opts, params, stop);
        g_minerThreadActive = false;
    });
}

static void StopMiningThread(CMiner& miner) {
    std::lock_guard<std::mutex> lk(g_minerMutex);
    if (!g_minerThreadActive.load()) return;
    miner.Stop();
    if (g_minerThread.joinable()) g_minerThread.join();
    miner.running = false;
    g_minerThreadActive = false;
}

static void RunMinerLoop(CBlockchain& chain, CTxMemPool& mempool, CMiner& miner,
                         CNetServer& net, const NodeOptions& opts, const ChainParams& params,
                         std::atomic<bool>& stop) {
    while (!stop.load()) {
        {
            std::lock_guard<std::mutex> lk(chain.GetMutex());
            if (miner.stopRequested.load()) break;
            if (!miner.IsRunning()) break;
            if (miner.GetMiningAddress().empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                continue;
            }
            const CBlockIndex* tip = chain.GetTip();
            if (!tip) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            int64_t height = tip->height + 1;
            // difficulty
            int64_t firstTime = tip->timestamp;
            int64_t intervalStart = (height / params.difficultyInterval) * params.difficultyInterval;
            if (intervalStart > 0) {
                CBlock firstBlk;
                if (chain.GetBlockByHeight(intervalStart, firstBlk))
                    firstTime = firstBlk.header.timestamp;
            }
            uint32_t bits = GetNextWorkRequired(tip->timestamp, tip->height, tip->bits,
                                                firstTime, params);
            uint32_t timestamp = (uint32_t)time(nullptr);
            if ((int64_t)timestamp <= tip->timestamp) timestamp = tip->timestamp + 1;

            int64_t fees = 0;
            CBlock candidate = CMiner::CreateCandidateBlock(height, bits, timestamp,
                                                            chain.GetTipHash(),
                                                            mempool, chain.GetView(),
                                                            miner.GetMiningAddress(),
                                                            params.addressVersion, fees);

            // mine
            uint256 target = TargetFromBits(bits);
            uint256 hash;
            uint32_t nonce = 0;
            bool found = false;
            auto headerSer = SerializeBlockHeader(candidate.header);
            uint8_t hdr[80];
            std::memcpy(hdr, headerSer.data(), 80);
            while (!stop.load() && !miner.stopRequested.load()) {
                uint8_t b[4];
                WriteU32LE(b, nonce);
                hdr[76] = b[0]; hdr[77] = b[1]; hdr[78] = b[2]; hdr[79] = b[3];
                hash = SHA256d(hdr, 80);
                miner.totalHashes.fetch_add(1);
                if (hash <= target) {
                    candidate.header.nonce = nonce;
                    found = true;
                    break;
                }
                ++nonce;
                if (nonce == 0) {
                    // extraNonce: rebuild coinbase (change extraNonce -> rebuild merkle)
                    // placeholder: adjust coinbase scriptSig
                    // implementasi sederhana: ubah timestamp +1 dan rebuild
                    candidate.header.timestamp += 1;
                    candidate.header.merkleRoot = ComputeMerkleRoot(candidate.vtx);
                    headerSer = SerializeBlockHeader(candidate.header);
                    std::memcpy(hdr, headerSer.data(), 80);
                }
            }
            if (!found) continue;

            // validasi + apply
            std::string error;
            ReorgResult r = TryAcceptBlock(chain, candidate, mempool);
            if (r.ok) {
                miner.blocksFound.fetch_add(1);
                miner.lastHeightMined = chain.GetHeight();
                // relay via INV (spec: Miner -> INV -> Peer -> GETDATA -> BLOCK)
                // broadcast block penuh ke peer yang cepat bisa membanjiri
                // socket peer yang masih sync; INV memungkinkan peer
                // meminta sesuai kecepatannya sendiri.
                uint256 blkHash = candidate.GetHash();
                net.BroadcastMessage("inv", SerializeInv({{InvType::BLOCK, blkHash}}));
                // update miner reward stats
                int64_t subsidy = GetBlockSubsidy(chain.GetHeight());
                miner.immatureReward += subsidy + fees;
                // clean mempool
                std::vector<uint256> removed;
                mempool.RemoveSpent(chain.GetView(), chain.GetHeight(), removed);
                if (opts.generateBlocks > 0 && chain.GetHeight() >= opts.generateBlocks) {
                    // target tercapai
                    break;
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    InstallCrashHandlers();
    NodeOptions opts = ParseArgs(argc, argv);
    ChainParams params = GetParams(opts.network); // salin; port dapat di-override
    if (opts.port != 0) params.defaultPort = opts.port;
    if (opts.rpcPort != 0) params.rpcPort = opts.rpcPort;

    std::printf("CDX Node — network: %s, data: %s\n", opts.network.c_str(), opts.dataDir.c_str());
    std::printf("CDX magic: 0x%08x, port: %u, rpc port: %u\n",
                params.networkMagic, params.defaultPort, params.rpcPort);

    // storage + blockchain
    CBlockStorage storage(opts.dataDir);
    CBlockchain blockchain(params, &storage);
    std::string error;
    if (!blockchain.Init(error)) {
        std::fprintf(stderr, "blockchain init failed: %s\n", error.c_str());
        return 1;
    }
    std::printf("chain height: %lld, tip: %s\n",
                (long long)blockchain.GetHeight(), blockchain.GetTipHash().getHex().c_str());

    // mempool
    CTxMemPool mempool;

    // wallet
    std::filesystem::create_directories(opts.dataDir + "/wallets");
    CWallet wallet;
    wallet.versionByte = params.addressVersion;
    bool walletExists = false;
    {
        // load wallet.dat jika ada
        std::string walletPath = opts.dataDir + "/wallets/wallet.dat";
        std::ifstream in(walletPath, std::ios::binary);
        if (in.good()) {
            in.seekg(0, std::ios::end);
            std::streamsize size = in.tellg();
            in.seekg(0);
            std::vector<uint8_t> data((size_t)size);
            in.read((char*)data.data(), size);
            in.close();
            try {
                wallet.keystore = CKeystore::Deserialize(data);
                walletExists = true;
            } catch (const std::exception& e) {
                std::fprintf(stderr, "wallet load failed: %s\n", e.what());
            }
        }
        if (!walletExists) {
            // wallet baru
            wallet.Unlock(opts.walletPassword);
            CKeyPair first = wallet.GenerateNewAddress();
            std::printf("new wallet created, first address: %s\n", first.address.c_str());
        } else {
            wallet.Unlock(opts.walletPassword);
            std::printf("wallet loaded (%zu keys)\n", wallet.KeyCount());
        }
        if (opts.rescan) {
            std::string re;
            int64_t n = WalletRescan(wallet, blockchain, re);
            std::printf("wallet rescan: %lld transactions found\n", (long long)n);
        }
        // simpan wallet
        auto ser = wallet.keystore.Serialize();
        std::ofstream out(walletPath, std::ios::binary | std::ios::trunc);
        if (out.good()) {
            out.write((const char*)ser.data(), (std::streamsize)ser.size());
            out.close();
        }
    }

    // P2P
    CNetServer net(params, nullptr);
    CNodeHandler handler(blockchain, mempool, net, &wallet, nullptr, opts);
    net.SetHandler(&handler);

    if (!opts.disableNetwork) {
        std::string nerr;
        if (!net.Start(nerr)) {
            std::fprintf(stderr, "p2p start failed: %s\n", nerr.c_str());
            return 1;
        }
        // koneksi ke peer seed (auto-reconnect)
        for (const auto& c : opts.connect) {
            size_t colon = c.rfind(':');
            if (colon == std::string::npos) continue;
            std::string host = c.substr(0, colon);
            uint16_t port = (uint16_t)std::atoi(c.substr(colon + 1).c_str());
            std::printf("connecting to %s:%u\n", host.c_str(), port);
            net.AddTarget(host, port);
        }
    }

    // RPC
    CRpcServer rpc(params, opts.rpcUser, opts.rpcPassword);
    CMiner miner;
    miner.SetMiningAddress(opts.miningAddress.empty() ? "" : opts.miningAddress, params.addressVersion);
    if (opts.miningAddress.empty() && !opts.disableMining) {
        // default: gunakan address wallet pertama
        auto addrs = wallet.GetAddresses();
        if (!addrs.empty()) miner.SetMiningAddress(addrs[0], params.addressVersion);
    }
    std::function<bool(const CTransaction&)> broadcastTxFn = [&](const CTransaction& tx) {
        auto ser = SerializeTransaction(tx);
        net.BroadcastMessage("tx", ser);
        return true;
    };
    std::function<void()> stopMiningFn = [&]() { miner.Stop(); };
    RegisterRpcMethods(rpc, &blockchain, &mempool, &wallet, &miner, &net, &params,
                       broadcastTxFn, stopMiningFn);

    // method tambahan CLI-specific
    rpc.Register("getaddresses", [&](const std::vector<std::string>&) {
        std::string out = "[";
        auto addrs = wallet.GetAddresses();
        for (size_t i = 0; i < addrs.size(); ++i) {
            if (i) out += ",";
            out += "\"" + addrs[i] + "\"";
        }
        out += "]";
        return out;
    });
    rpc.Register("sendtoaddress", [&](const std::vector<std::string>& p) {
        if (p.size() < 2) return std::string("\"error: usage sendtoaddress <addr> <amount>\"");
        std::lock_guard<std::mutex> lk(blockchain.GetMutex());
        int64_t amount = ParseValue(p[1]);
        CTransaction tx;
        uint256 txid;
        std::string err;
        if (!wallet.CreateTransaction(blockchain.GetView(), blockchain.GetHeight(),
                                      p[0], amount, tx, txid, err)) {
            return std::string("\"error: " + err + "\"");
        }
        // masuk mempool
        int64_t fee = 0;
        if (mempool.CheckTx(tx, blockchain.GetView(), blockchain.GetHeight(), fee, err)) {
            mempool.AddUnchecked(tx, fee, blockchain.GetHeight(), (int64_t)time(nullptr));
            auto ser = SerializeTransaction(tx);
            net.BroadcastMessage("tx", ser);
        }
        return std::string("\"" + txid.getHex() + "\"");
    });
    rpc.Register("startmining", [&](const std::vector<std::string>&) {
        if (miner.GetMiningAddress().empty()) {
            auto addrs = wallet.GetAddresses();
            if (addrs.empty()) return std::string("\"error: no mining address\"");
            miner.SetMiningAddress(addrs[0], params.addressVersion);
        }
        StartMiningThread(blockchain, mempool, miner, net, opts, params, g_stop);
        return std::string("\"mining started\"");
    });
    rpc.Register("stopmining", [&](const std::vector<std::string>&) {
        StopMiningThread(miner);
        return std::string("\"mining stopped\"");
    });
    rpc.Register("setminingaddress", [&](const std::vector<std::string>& p) {
        if (p.empty()) return std::string("\"error: missing address\"");
        miner.SetMiningAddress(p[0], params.addressVersion);
        return std::string("\"mining address set\"");
    });
    rpc.Register("getminingaddress", [&](const std::vector<std::string>&) {
        return std::string("\"" + miner.GetMiningAddress() + "\"");
    });
    rpc.Register("addnode", [&](const std::vector<std::string>& p) {
        if (p.empty()) return std::string("\"error: missing node\"");
        size_t colon = p[0].rfind(':');
        std::string host = p[0];
        uint16_t port = params.defaultPort;
        if (colon != std::string::npos) {
            host = p[0].substr(0, colon);
            port = (uint16_t)std::atoi(p[0].substr(colon + 1).c_str());
        }
        net.AddTarget(host, port);
        return std::string("\"connecting\"");
    });

    std::string rerr;
    if (!rpc.Start(rerr)) {
        std::fprintf(stderr, "rpc start failed: %s\n", rerr.c_str());
    } else {
        std::printf("RPC listening on 127.0.0.1:%u\n", params.rpcPort);
    }

    // mining loop jika diaktifkan
    if (!opts.disableMining) {
        StartMiningThread(blockchain, mempool, miner, net, opts, params, g_stop);
    }

    std::printf("CDX node running. Press Ctrl-C to stop.\n");
    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    StopMiningThread(miner);
    net.Stop();
    rpc.Stop();

    // simpan wallet terakhir
    {
        auto ser = wallet.keystore.Serialize();
        std::ofstream out(opts.dataDir + "/wallets/wallet.dat", std::ios::binary | std::ios::trunc);
        if (out.good()) {
            out.write((const char*)ser.data(), (std::streamsize)ser.size());
            out.close();
        }
    }
    std::printf("CDX node stopped.\n");
    return 0;
}
