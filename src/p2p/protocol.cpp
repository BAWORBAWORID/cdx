#include "p2p/protocol.h"
#include "crypto/hash.h"
#include "crypto/encoding.h"
#include "transaction/serializer.h"
#include <cstring>

namespace cdx {

std::vector<uint8_t> SerializeVersion(const CVersionMessage& v) {
    CSerializer s;
    s.WriteU32((uint32_t)v.version);
    s.WriteU64((uint64_t)v.services);
    s.WriteU64((uint64_t)v.timestamp);
    // addrRecv 26 byte
    s.WriteBytes(v.addrYou, 26);
    s.WriteBytes(v.addrMe, 26);
    s.WriteU64(v.nonce);
    s.WriteVarStr(std::vector<uint8_t>(v.userAgent.begin(), v.userAgent.end()));
    s.WriteU32((uint32_t)v.startHeight);
    s.WriteU8(v.relay ? 1 : 0);
    return std::move(s.buf);
}

bool DeserializeVersion(const std::vector<uint8_t>& payload, CVersionMessage& v) {
    CDeserializer d(payload.data(), payload.size());
    uint32_t ver;
    if (!d.ReadU32(ver)) return false;
    v.version = (int32_t)ver;
    uint64_t svc;
    if (!d.ReadU64(svc)) return false;
    v.services = (int64_t)svc;
    uint64_t ts;
    if (!d.ReadU64(ts)) return false;
    v.timestamp = (int64_t)ts;
    if (!d.ReadBytes(v.addrYou, 26)) return false;
    if (!d.ReadBytes(v.addrMe, 26)) return false;
    if (!d.ReadU64(v.nonce)) return false;
    std::vector<uint8_t> ua;
    if (!d.ReadVarStr(ua)) return false;
    v.userAgent.assign(ua.begin(), ua.end());
    uint32_t sh;
    if (!d.ReadU32(sh)) return false;
    v.startHeight = (int32_t)sh;
    uint8_t relay;
    if (!d.ReadU8(relay)) return false;
    v.relay = relay != 0;
    return true;
}

bool BuildMessage(uint32_t magic, const std::string& command,
                  const std::vector<uint8_t>& payload, std::vector<uint8_t>& out) {
    if (command.size() > 12 || payload.size() > MAX_MESSAGE_SIZE) return false;
    out.clear();
    out.reserve(24 + payload.size());
    uint8_t m[4];
    WriteU32LE(m, magic);
    out.insert(out.end(), m, m + 4);
    char cmd[12] = {0};
    std::memcpy(cmd, command.c_str(), command.size());
    out.insert(out.end(), cmd, cmd + 12);
    uint8_t len[4];
    WriteU32LE(len, (uint32_t)payload.size());
    out.insert(out.end(), len, len + 4);
    uint8_t checksum[32];
    SHA256d(payload.data(), payload.size(), checksum);
    out.insert(out.end(), checksum, checksum + 4);
    out.insert(out.end(), payload.begin(), payload.end());
    return true;
}

int ParseMessage(const uint8_t* data, size_t len, uint32_t magic,
                 CNetMessage& msg, size_t& consumed) {
    if (len < 24) return -1; // belum lengkap
    if (ReadU32LE(data) != magic) return 0; // magic salah
    std::string command((const char*)data + 4, 12);
    // strip null padding
    size_t end = command.find('\0');
    if (end != std::string::npos) command = command.substr(0, end);
    if (!IsKnownCommand(command)) return 0;
    uint32_t payloadLen = ReadU32LE(data + 16);
    if (payloadLen > MAX_MESSAGE_SIZE) return 0;
    if (len < 24 + payloadLen) return -1; // belum lengkap
    // checksum
    uint8_t checksum[32];
    SHA256d(data + 24, payloadLen, checksum);
    if (std::memcmp(checksum, data + 20, 4) != 0) return 0;
    msg.command = command;
    msg.payload.assign(data + 24, data + 24 + payloadLen);
    consumed = 24 + payloadLen;
    return 1;
}

std::vector<uint8_t> SerializeInv(const std::vector<CInv>& inv) {
    CSerializer s;
    s.WriteVarInt(inv.size());
    for (const auto& i : inv) {
        s.WriteU32((uint32_t)i.type);
        s.WriteUint256(i.hash);
    }
    return std::move(s.buf);
}

bool DeserializeInv(const std::vector<uint8_t>& payload, std::vector<CInv>& inv) {
    CDeserializer d(payload.data(), payload.size());
    uint64_t n;
    if (!d.ReadVarInt(n)) return false;
    if (n > MAX_INV_PER_MESSAGE) return false;
    inv.clear();
    inv.reserve(n);
    for (uint64_t i = 0; i < n; ++i) {
        uint32_t type;
        uint256 hash;
        if (!d.ReadU32(type)) return false;
        if (!d.ReadUint256(hash)) return false;
        inv.push_back({(InvType)type, hash});
    }
    return true;
}

} // namespace cdx
