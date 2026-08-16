#include "storage/blocks.h"
#include "transaction/serializer.h"
#include "crypto/encoding.h"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace fs = std::filesystem;

namespace cdx {

CBlockStorage::CBlockStorage(const std::string& dataDir) : dir(dataDir), blocksDir(dataDir + "/blocks") {
    fs::create_directories(blocksDir);
}

std::string CBlockStorage::BlockFilePath(int fileNum) {
    char name[64];
    std::snprintf(name, sizeof(name), "blk%05d.dat", fileNum);
    return blocksDir + "/" + name;
}

bool CBlockStorage::WriteBlock(const CBlock& blk, int64_t height) {
    auto ser = SerializeBlock(blk);
    uint256 hash = blk.GetHash();
    int fileNum = AppendToFile(ser);
    if (fileNum < 0) return false;
    // record offset
    std::ifstream in(BlockFilePath(fileNum), std::ios::binary | std::ios::ate);
    int64_t size = (int64_t)ser.size();
    int64_t offset = (int64_t)in.tellg() - size;
    in.close();
    index[hash] = std::make_tuple(height, fileNum, offset, size);
    SaveIndex();
    return true;
}

int CBlockStorage::AppendToFile(const std::vector<uint8_t>& data) {
    // tentukan file terakhir
    int fileNum = 0;
    for (const auto& entry : index) {
        int f = std::get<1>(entry.second);
        if (f > fileNum) fileNum = f;
    }
    // cek ukuran file terakhir
    std::string path = BlockFilePath(fileNum);
    int64_t size = 0;
    {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (in.good()) size = (int64_t)in.tellg();
    }
    const int64_t MAX_FILE = 128 * 1024 * 1024; // 128 MB per file
    if (size > 0 && size + (int64_t)data.size() > MAX_FILE) {
        ++fileNum;
        path = BlockFilePath(fileNum);
    }
    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out.good()) return -1;
    out.write((const char*)data.data(), (std::streamsize)data.size());
    out.flush();
    out.close();
    return fileNum;
}

bool CBlockStorage::ReadFromFile(int fileNum, int64_t offset, int64_t size, std::vector<uint8_t>& out) {
    std::ifstream in(BlockFilePath(fileNum), std::ios::binary);
    if (!in.good()) return false;
    in.seekg(offset);
    out.resize((size_t)size);
    in.read((char*)out.data(), size);
    return in.good();
}

bool CBlockStorage::ReadBlock(const uint256& hash, CBlock& blk) {
    LoadIndex();
    auto it = index.find(hash);
    if (it == index.end()) return false;
    auto [height, fileNum, offset, size] = it->second;
    std::vector<uint8_t> data;
    if (!ReadFromFile(fileNum, offset, size, data)) return false;
    if (!DeserializeBlock(data.data(), data.size(), blk)) return false;
    if (blk.GetHash() != hash) return false;
    return true;
}

bool CBlockStorage::HasBlock(const uint256& hash) {
    LoadIndex();
    return index.count(hash) > 0;
}

size_t CBlockStorage::BlockCount() {
    LoadIndex();
    return index.size();
}

void CBlockStorage::SaveIndex() {
    std::string path = blocksDir + "/index.dat";
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.good()) return;
    uint64_t n = index.size();
    uint8_t hdr[8];
    WriteU64LE(hdr, n);
    out.write((const char*)hdr, 8);
    for (const auto& kv : index) {
        uint8_t hashBytes[32];
        kv.first.getBytesLE(hashBytes);
        out.write((const char*)hashBytes, 32);
        int64_t h = std::get<0>(kv.second);
        int f = std::get<1>(kv.second);
        int64_t off = std::get<2>(kv.second);
        int64_t sz = std::get<3>(kv.second);
        uint8_t meta[8];
        WriteU64LE(meta, (uint64_t)h);
        out.write((const char*)meta, 8);
        WriteU32LE(meta, (uint32_t)f);
        out.write((const char*)meta, 4);
        WriteU64LE(meta, (uint64_t)off);
        out.write((const char*)meta, 8);
        WriteU64LE(meta, (uint64_t)sz);
        out.write((const char*)meta, 8);
    }
    out.close();
}

void CBlockStorage::LoadIndex() {
    if (loaded) return;
    loaded = true;
    std::string path = blocksDir + "/index.dat";
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) return;
    uint8_t hdr[8];
    in.read((char*)hdr, 8);
    uint64_t n = ReadU64LE(hdr);
    if (n > 100000000) return;
    for (uint64_t i = 0; i < n; ++i) {
        uint8_t hashBytes[32], meta[8];
        in.read((char*)hashBytes, 32);
        in.read((char*)meta, 8);
        int64_t height = (int64_t)ReadU64LE(meta);
        in.read((char*)meta, 4);
        int fileNum = (int)ReadU32LE(meta);
        in.read((char*)meta, 8);
        int64_t offset = (int64_t)ReadU64LE(meta);
        in.read((char*)meta, 8);
        int64_t size = (int64_t)ReadU64LE(meta);
        if (!in.good()) break;
        uint256 hash;
        hash.setBytesLE(hashBytes);
        index[hash] = std::make_tuple(height, fileNum, offset, size);
    }
}

bool CBlockStorage::SaveChainState(const CCoinsView& view, int64_t height,
                                   const uint256& tipHash, const std::vector<uint256>& byHeight) {
    std::string path = dir + "/chainstate.dat";
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.good()) return false;
    // header: magic + height + tipHash + byHeight count
    out.write("CDXS", 4);
    uint8_t meta[8];
    WriteU64LE(meta, (uint64_t)height);
    out.write((const char*)meta, 8);
    uint8_t tip[32];
    tipHash.getBytesLE(tip);
    out.write((const char*)tip, 32);
    WriteU64LE(meta, (uint64_t)byHeight.size());
    out.write((const char*)meta, 8);
    for (const auto& h : byHeight) {
        h.getBytesLE(tip);
        out.write((const char*)tip, 32);
    }
    // UTXO count + entries
    WriteU64LE(meta, (uint64_t)view.utxo.size());
    out.write((const char*)meta, 8);
    for (const auto& kv : view.utxo) {
        uint8_t hashBytes[32];
        kv.first.hash.getBytesLE(hashBytes);
        out.write((const char*)hashBytes, 32);
        WriteU32LE(meta, kv.first.n);
        out.write((const char*)meta, 4);
        WriteU64LE(meta, (uint64_t)kv.second.value);
        out.write((const char*)meta, 8);
        WriteU64LE(meta, (uint64_t)kv.second.height);
        out.write((const char*)meta, 8);
        uint8_t flags = kv.second.isCoinbase ? 1 : 0;
        out.write((const char*)&flags, 1);
        uint64_t scriptLen = kv.second.scriptPubKey.size();
        WriteU64LE(meta, scriptLen);
        out.write((const char*)meta, 8);
        out.write((const char*)kv.second.scriptPubKey.data(), (std::streamsize)scriptLen);
    }
    out.close();
    return true;
}

bool CBlockStorage::LoadChainState(CCoinsView& view, int64_t& height,
                                   uint256& tipHash, std::vector<uint256>& byHeight) {
    std::string path = dir + "/chainstate.dat";
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) return false;
    char magic[4];
    in.read(magic, 4);
    if (std::string(magic, 4) != "CDXS") return false;
    uint8_t meta[8];
    in.read((char*)meta, 8);
    height = (int64_t)ReadU64LE(meta);
    uint8_t tip[32];
    in.read((char*)tip, 32);
    tipHash.setBytesLE(tip);
    in.read((char*)meta, 8);
    uint64_t nHeight = ReadU64LE(meta);
    if (nHeight > 100000000) return false;
    byHeight.clear();
    byHeight.reserve(nHeight);
    for (uint64_t i = 0; i < nHeight; ++i) {
        in.read((char*)tip, 32);
        uint256 h;
        h.setBytesLE(tip);
        byHeight.push_back(h);
    }
    in.read((char*)meta, 8);
    uint64_t nUtxo = ReadU64LE(meta);
    if (nUtxo > 1000000000) return false;
    view.utxo.clear();
    for (uint64_t i = 0; i < nUtxo; ++i) {
        uint8_t hashBytes[32], flags;
        in.read((char*)hashBytes, 32);
        in.read((char*)meta, 4);
        COutPoint out;
        out.hash.setBytesLE(hashBytes);
        out.n = ReadU32LE(meta);
        in.read((char*)meta, 8);
        int64_t value = (int64_t)ReadU64LE(meta);
        in.read((char*)meta, 8);
        int64_t utxoHeight = (int64_t)ReadU64LE(meta);
        in.read((char*)&flags, 1);
        in.read((char*)meta, 8);
        uint64_t scriptLen = ReadU64LE(meta);
        if (scriptLen > 100000) return false;
        CUTXO coin;
        coin.value = value;
        coin.height = utxoHeight;
        coin.isCoinbase = flags != 0;
        coin.scriptPubKey.resize(scriptLen);
        in.read((char*)coin.scriptPubKey.data(), (std::streamsize)scriptLen);
        view.utxo[out] = std::move(coin);
    }
    in.close();
    return true;
}

bool CBlockStorage::SavePeers(const std::vector<std::string>& addresses) {
    std::string path = dir + "/peers.dat";
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.good()) return false;
    uint8_t meta[8];
    WriteU64LE(meta, (uint64_t)addresses.size());
    out.write((const char*)meta, 8);
    for (const auto& a : addresses) {
        WriteU64LE(meta, (uint64_t)a.size());
        out.write((const char*)meta, 8);
        out.write(a.data(), (std::streamsize)a.size());
    }
    out.close();
    return true;
}

std::vector<std::string> CBlockStorage::LoadPeers() {
    std::vector<std::string> out;
    std::string path = dir + "/peers.dat";
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) return out;
    uint8_t meta[8];
    in.read((char*)meta, 8);
    uint64_t n = ReadU64LE(meta);
    if (n > 1000000) return out;
    for (uint64_t i = 0; i < n; ++i) {
        in.read((char*)meta, 8);
        uint64_t len = ReadU64LE(meta);
        if (len > 512) break;
        std::string a(len, '\0');
        in.read(&a[0], (std::streamsize)len);
        if (in.good()) out.push_back(a);
    }
    return out;
}

} // namespace cdx
