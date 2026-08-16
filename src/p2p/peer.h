#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <functional>
#include "p2p/protocol.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Peer — satu koneksi TCP P2P.
// Handshake: version -> version -> verack -> verack
// Kemudian relay tx/block + chain sync.
// ---------------------------------------------------------------------------

class CNode {
public:
    int fd = -1;
    std::string addr;             // "host:port"
    bool inbound = false;
    bool connected = false;
    bool handshakeDone = false;
    bool verackReceived = false;
    CVersionMessage theirVersion;
    int64_t lastMessageTime = 0;
    int64_t lastSendTime = 0;
    int64_t lastPingTime = 0;
    uint64_t pingNonce = 0;
    uint64_t nonce = 0;
    int misbehaviorScore = 0;
    bool disconnected = false;

    std::vector<uint8_t> recvBuffer;

    CNode() = default;
    CNode(int fd_, const std::string& addr_, bool inbound_)
        : fd(fd_), addr(addr_), inbound(inbound_) {}

    void MarkDisconnected() { disconnected = true; }
    bool IsDisconnected() const { return disconnected; }
};

// callback interface untuk node server
struct INodeHandler {
    virtual ~INodeHandler() = default;
    virtual void OnMessage(CNode& node, const CNetMessage& msg) = 0;
    virtual void OnDisconnect(CNode& node) = 0;
};

} // namespace cdx
