#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <thread>
#include <memory>
#include "p2p/peer.h"
#include "p2p/protocol.h"
#include "config/networks.h"

namespace cdx {

// ---------------------------------------------------------------------------
// P2P server — TCP listener + koneksi keluar + relay.
// ---------------------------------------------------------------------------
class CNetServer {
public:
    CNetServer(const ChainParams& params, INodeHandler* handler);
    ~CNetServer();

    // set handler (dapat dipanggil setelah konstruksi)
    void SetHandler(INodeHandler* h) { handler = h; }

    bool Start(std::string& error);
    void Stop();

    // koneksi keluar ke peer (satu kali)
    bool ConnectTo(const std::string& host, uint16_t port);

    // target peer yang selalu dicoba koneksi (auto-reconnect)
    void AddTarget(const std::string& host, uint16_t port);

    // broadcast pesan ke semua peer yang handshake selesai (kecuali exclude)
    void BroadcastMessage(const std::string& command, const std::vector<uint8_t>& payload,
                          int excludeFd = -1);

    // kirim langsung ke satu peer
    bool SendTo(int fd, const std::string& command, const std::vector<uint8_t>& payload);

    size_t GetPeerCount() const;
    std::vector<std::pair<std::string, bool>> GetPeerList() const; // (addr, handshakeDone)

    uint16_t GetPort() const { return params.defaultPort; }
    uint32_t GetMagic() const { return params.networkMagic; }

    // nonce node ini (untuk deteksi self-connection)
    uint64_t localNonce;

private:
    const ChainParams& params;
    INodeHandler* handler;
    std::atomic<bool> running{false};
    std::thread acceptThread;
    std::thread connectThread;
    mutable std::mutex peersMutex;
    std::map<int, std::shared_ptr<CNode>> peers; // fd -> node
    std::vector<std::string> targets; // "host:port" untuk auto-reconnect
    int listenFd = -1;
    uint16_t bindPort = 0;

    void AcceptLoop();
    void ReadLoop(std::shared_ptr<CNode> node);
    bool WriteTo(int fd, const std::vector<uint8_t>& data); // false = gagal (stream rusak)
    void ConnectLoop();
    bool HasTargetConnection(const std::string& target) const;

    // proses buffer masuk: parse frame, dispatch ke handler
    void ProcessBuffer(std::shared_ptr<CNode> node);
};

} // namespace cdx
