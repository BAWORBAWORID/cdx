#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "crypto/uint256.h"
#include "blockchain/block.h"
#include "transaction/transaction.h"
#include "config/networks.h"

namespace cdx {

// ---------------------------------------------------------------------------
// P2P protocol CDX.
// Message framing (bitcoin-style):
//   magic (4) | command (12, null-padded) | length (4 LE) | checksum (4) | payload
// checksum = first 4 bytes of SHA256d(payload)
//
// Messages: version, verack, addr, getaddr, inv, getdata, tx, block,
//           getblocks, getheaders, headers, ping, pong
// ---------------------------------------------------------------------------

inline constexpr size_t MAX_MESSAGE_SIZE = 4 * 1024 * 1024; // 4 MB
inline constexpr size_t MAX_INV_PER_MESSAGE = 50000;

enum class InvType : uint32_t {
    TX = 1,
    BLOCK = 2,
};

struct CInv {
    InvType type;
    uint256 hash;

    bool operator==(const CInv& o) const { return type == o.type && hash == o.hash; }
    bool operator<(const CInv& o) const {
        if (type != o.type) return (uint32_t)type < (uint32_t)o.type;
        return hash < o.hash;
    }
};

// versi protokol CDX
inline constexpr int32_t PROTOCOL_VERSION = 10001;
inline constexpr int32_t MIN_PROTOCOL_VERSION = 10001;

// struktur version payload
struct CVersionMessage {
    int32_t version = PROTOCOL_VERSION;
    int64_t services = 0;
    int64_t timestamp = 0;
    uint8_t addrMe[26] = {0}; // not used
    uint8_t addrYou[26] = {0};
    uint64_t nonce = 0;
    std::string userAgent = "/CDX:0.1.0/";
    int32_t startHeight = 0;
    bool relay = true;
};

// serialize/deserialize payload
std::vector<uint8_t> SerializeVersion(const CVersionMessage& v);
bool DeserializeVersion(const std::vector<uint8_t>& payload, CVersionMessage& v);

// --- message framing ---
struct CNetMessage {
    std::string command;
    std::vector<uint8_t> payload;
};

// frame satu pesan; mengembalikan false bila command invalid / payload > max
bool BuildMessage(uint32_t magic, const std::string& command,
                  const std::vector<uint8_t>& payload, std::vector<uint8_t>& out);

// parse stream: mengembalikan pesan lengkap pertama dari buffer, dan sisa.
// Mengembalikan -1 bila frame tidak lengkap; 0 bila magic salah; 1 bila ok.
int ParseMessage(const uint8_t* data, size_t len, uint32_t magic,
                 CNetMessage& msg, size_t& consumed);

// --- inv ---
std::vector<uint8_t> SerializeInv(const std::vector<CInv>& inv);
bool DeserializeInv(const std::vector<uint8_t>& payload, std::vector<CInv>& inv);

// --- block serialization via serializer (dipanggil dari sync) ---

// command helper
inline bool IsKnownCommand(const std::string& cmd) {
    static const std::vector<std::string> known = {
        "version", "verack", "addr", "getaddr", "inv", "getdata", "tx",
        "block", "getblocks", "getheaders", "headers", "ping", "pong"
    };
    for (const auto& k : known) if (k == cmd) return true;
    return false;
}

} // namespace cdx
