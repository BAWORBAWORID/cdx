#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace cdx {

struct MongoPeer {
    std::string addr;       // "host:port"
    std::string network;
    int64_t lastSeen = 0;
};

// ---------------------------------------------------------------------------
// Minimal MongoDB client (OP_MSG + SCRAM-SHA-256 + TLS via OpenSSL).
// Digunakan HANYA untuk peer registry / discovery — BUKAN konsensus storage.
// (Spek CDX: MongoDB optional, non-consensus.)
// ---------------------------------------------------------------------------
class CMongoClient {
public:
    CMongoClient();
    ~CMongoClient();
    CMongoClient(const CMongoClient&) = delete;
    CMongoClient& operator=(const CMongoClient&) = delete;

    // uri: mongodb+srv://user:pass@host/db?params  atau  mongodb://user:pass@host:port/db
    // melakukan koneksi TLS + auth SCRAM-SHA-256 + ping ("check mongo").
    bool Connect(const std::string& uri, std::string& err);
    void Disconnect();
    bool IsConnected() const { return connected_; }

    bool Ping(std::string& err);

    // register/update peer ini (upsert by _id = network + ":" + addr)
    bool UpsertPeer(const std::string& network, const std::string& addr,
                    int64_t lastSeen, std::string& err);

    // ambil peer lain (kecuali excludeAddr), network sama
    bool FetchPeers(const std::string& network, const std::string& excludeAddr,
                    std::vector<MongoPeer>& out, std::string& err);

    // hapus peer yang lastSeen < cutoff (stale)
    bool CleanupStale(const std::string& network, int64_t cutoff, std::string& err);

private:
    struct Impl;
    Impl* p_;
    bool connected_ = false;
};

} // namespace cdx
