#include "p2p/server.h"
#include "crypto/encoding.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>
#include <chrono>
#include <thread>
#include <openssl/rand.h>

namespace cdx {

CNetServer::CNetServer(const ChainParams& params, INodeHandler* handler)
    : params(params), handler(handler) {
    RAND_bytes((uint8_t*)&localNonce, sizeof(localNonce));
    if (localNonce == 0) localNonce = 1;
}

CNetServer::~CNetServer() {
    Stop();
}

static void SetNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

bool CNetServer::Start(std::string& error) {
    if (running.load()) return true;
    listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd < 0) {
        error = "cannot create socket";
        return false;
    }
    int opt = 1;
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(params.defaultPort);
    if (bind(listenFd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        error = "cannot bind to port " + std::to_string(params.defaultPort);
        close(listenFd);
        listenFd = -1;
        return false;
    }
    if (listen(listenFd, 32) != 0) {
        error = "cannot listen";
        close(listenFd);
        listenFd = -1;
        return false;
    }
    SetNonBlocking(listenFd);
    running = true;
    acceptThread = std::thread([this]() { AcceptLoop(); });
    connectThread = std::thread([this]() { ConnectLoop(); });
    return true;
}

void CNetServer::Stop() {
    running = false;
    if (listenFd >= 0) {
        close(listenFd);
        listenFd = -1;
    }
    if (connectThread.joinable()) connectThread.join();
    {
        std::lock_guard<std::mutex> lk(peersMutex);
        for (auto& kv : peers) {
            if (kv.second->fd >= 0) close(kv.second->fd);
            kv.second->fd = -1;
        }
        peers.clear();
    }
    if (acceptThread.joinable()) acceptThread.join();
}

void CNetServer::AcceptLoop() {
    while (running.load()) {
        struct sockaddr_in clientAddr;
        socklen_t len = sizeof(clientAddr);
        int fd = accept(listenFd, (struct sockaddr*)&clientAddr, &len);
        if (fd < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        SetNonBlocking(fd);
        int opt = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
        char host[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, host, sizeof(host));
        std::string addrStr = std::string(host) + ":" + std::to_string(ntohs(clientAddr.sin_port));
        auto node = std::make_shared<CNode>(fd, addrStr, true);
        {
            std::lock_guard<std::mutex> lk(peersMutex);
            if (peers.size() >= 32) { // connection limit
                close(fd);
                continue;
            }
            peers[fd] = node;
        }
        std::thread([this, node]() { ReadLoop(node); }).detach();
    }
}

void CNetServer::AddTarget(const std::string& host, uint16_t port) {
    std::string t = host + ":" + std::to_string(port);
    {
        std::lock_guard<std::mutex> lk(peersMutex);
        for (const auto& x : targets)
            if (x == t) return;
        targets.push_back(t);
    }
    ConnectTo(host, port); // coba langsung; gagal akan diulang ConnectLoop
}

bool CNetServer::HasTargetConnection(const std::string& target) const {
    std::lock_guard<std::mutex> lk(peersMutex);
    for (const auto& kv : peers) {
        const auto& n = kv.second;
        if (!n->inbound && n->addr == target && !n->disconnected) return true;
    }
    return false;
}

void CNetServer::ConnectLoop() {
    while (running.load()) {
        std::vector<std::string> todo;
        {
            std::lock_guard<std::mutex> lk(peersMutex);
            todo = targets;
        }
        for (const auto& t : todo) {
            if (!running.load()) break;
            if (HasTargetConnection(t)) continue;
            size_t colon = t.rfind(':');
            if (colon == std::string::npos) continue;
            std::string host = t.substr(0, colon);
            uint16_t port = (uint16_t)std::atoi(t.substr(colon + 1).c_str());
            ConnectTo(host, port);
        }
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
}

bool CNetServer::ConnectTo(const std::string& host, uint16_t port) {
    struct addrinfo hints, *res = nullptr;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) return false;
    int fd = -1;
    for (struct addrinfo* p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        // timeout koneksi: non-blocking + poll
        SetNonBlocking(fd);
        int rc = connect(fd, p->ai_addr, p->ai_addrlen);
        if (rc != 0) {
            struct pollfd pf = {fd, POLLOUT, 0};
            rc = poll(&pf, 1, 5000);
            int err = 0;
            socklen_t elen = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
            if (rc <= 0 || err != 0) {
                close(fd);
                fd = -1;
                continue;
            }
        }
        break;
    }
    freeaddrinfo(res);
    if (fd < 0) return false;
    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    SetNonBlocking(fd);
    std::string addrStr = host + ":" + portStr;
    auto node = std::make_shared<CNode>(fd, addrStr, false);
    {
        std::lock_guard<std::mutex> lk(peersMutex);
        if (peers.size() >= 32) {
            close(fd);
            return false;
        }
        peers[fd] = node;
    }
    // outbound: kirim version dulu untuk memulai handshake
    CVersionMessage v;
    v.timestamp = (int64_t)time(nullptr);
    v.nonce = localNonce;
    auto verSer = SerializeVersion(v);
    SendTo(fd, "version", verSer);
    std::thread([this, node]() { ReadLoop(node); }).detach();
    return true;
}

// Kirim seluruh data. Mengembalikan false bila koneksi macet/putus —
// JANGAN pernah mengirim frame terpotong (itu merusak stream pesan).
// Peer yang gagal ditandai disconnected agar ReadLoop membersihkannya.
bool CNetServer::WriteTo(int fd, const std::vector<uint8_t>& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // tunggu writable — beri waktu lama (30s) agar peer yang
            // sedang sync (disk lambat) tidak terputus di tengah download
            struct pollfd pf = {fd, POLLOUT, 0};
            int rc = poll(&pf, 1, 30000);
            if (rc <= 0) return false;
            continue;
        }
        return false; // error
    }
    return true;
}

bool CNetServer::SendTo(int fd, const std::string& command, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> frame;
    if (!BuildMessage(params.networkMagic, command, payload, frame)) return false;
    std::lock_guard<std::mutex> lk(peersMutex);
    auto it = peers.find(fd);
    if (it == peers.end()) return false;
    if (!WriteTo(fd, frame)) {
        it->second->MarkDisconnected();
        return false;
    }
    return true;
}

void CNetServer::BroadcastMessage(const std::string& command, const std::vector<uint8_t>& payload,
                                  int excludeFd) {
    std::vector<uint8_t> frame;
    if (!BuildMessage(params.networkMagic, command, payload, frame)) return;
    std::lock_guard<std::mutex> lk(peersMutex);
    for (auto& kv : peers) {
        auto& node = kv.second;
        if (node->fd == excludeFd || !node->handshakeDone) continue;
        if (!WriteTo(node->fd, frame)) node->MarkDisconnected();
    }
}

size_t CNetServer::GetPeerCount() const {
    std::lock_guard<std::mutex> lk(peersMutex);
    size_t n = 0;
    for (const auto& kv : peers)
        if (!kv.second->disconnected) ++n;
    return n;
}

std::vector<std::pair<std::string, bool>> CNetServer::GetPeerList() const {
    std::lock_guard<std::mutex> lk(peersMutex);
    std::vector<std::pair<std::string, bool>> out;
    for (const auto& kv : peers)
        out.push_back({kv.second->addr, kv.second->handshakeDone});
    return out;
}

void CNetServer::ReadLoop(std::shared_ptr<CNode> node) {
    std::vector<uint8_t> tmp(64 * 1024);
    while (running.load() && !node->disconnected) {
        ssize_t n = ::recv(node->fd, tmp.data(), tmp.size(), 0);
        if (n > 0) {
            {
                std::lock_guard<std::mutex> lk(peersMutex);
                node->recvBuffer.insert(node->recvBuffer.end(), tmp.begin(), tmp.begin() + n);
                node->lastMessageTime = (int64_t)time(nullptr);
            }
            ProcessBuffer(node);
        } else if (n == 0) {
            break; // peer menutup koneksi
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // cek timeout idle (90 detik tanpa pesan)
            struct pollfd pf = {node->fd, POLLIN, 0};
            int rc = poll(&pf, 1, 1000);
            if (rc == 0) {
                if ((int64_t)time(nullptr) - node->lastMessageTime > 90) break;
                continue;
            }
            if (rc < 0) break;
        } else {
            break;
        }
    }
    // disconnect
    handler->OnDisconnect(*node);
    node->disconnected = true;
    {
        std::lock_guard<std::mutex> lk(peersMutex);
        auto it = peers.find(node->fd);
        if (it != peers.end()) peers.erase(it);
    }
    if (node->fd >= 0) {
        close(node->fd);
        node->fd = -1;
    }
}

void CNetServer::ProcessBuffer(std::shared_ptr<CNode> node) {
    // Platform PaaS (Railway/Koyeb/Heroku) melakukan health check HTTP ke
    // port yang di-expose. Node CDX bind protokol P2P (binary) di port itu,
    // sehingga health check gagal -> instance stuck "starting".
    // Solusi: deteksi request HTTP di awal buffer -> balas 200 OK (health OK),
    // tanpa mengganggu protokol P2P CDX (magic 0xCDA1CD01, bukan HTTP).
    {
        std::lock_guard<std::mutex> lk(peersMutex);
        static const char* httpMethods[] = {"GET ", "POST ", "HEAD ", "PUT ",
                                            "OPTIONS ", "DELETE ", "PATCH "};
        bool isHttp = false;
        for (const char* m : httpMethods) {
            size_t len = std::strlen(m);
            if (node->recvBuffer.size() >= len &&
                std::memcmp(node->recvBuffer.data(), m, len) == 0) {
                isHttp = true;
                break;
            }
        }
        if (isHttp) {
            const char* resp =
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                "Content-Length: 2\r\nConnection: close\r\n\r\nok";
            WriteTo(node->fd, std::vector<uint8_t>(resp, resp + std::strlen(resp)));
            node->MarkDisconnected();
            return;
        }
    }
    for (;;) {
        CNetMessage msg;
        size_t consumed = 0;
        {
            std::lock_guard<std::mutex> lk(peersMutex);
            int rc = ParseMessage(node->recvBuffer.data(), node->recvBuffer.size(),
                                  params.networkMagic, msg, consumed);
            if (rc < 0) return; // belum lengkap
            if (rc == 0) {
                // pesan invalid: malformed packet -> disconnect (peer scoring)
                node->misbehaviorScore += 100;
                node->recvBuffer.clear();
                if (node->misbehaviorScore >= 200) {
                    node->MarkDisconnected();
                }
                return;
            }
            node->recvBuffer.erase(node->recvBuffer.begin(), node->recvBuffer.begin() + consumed);
            node->lastMessageTime = (int64_t)time(nullptr);
        }
        handler->OnMessage(*node, msg);
    }
}

} // namespace cdx
