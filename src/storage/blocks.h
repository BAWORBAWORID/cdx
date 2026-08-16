#pragma once
#include <cstdint>
#include <map>
#include <string>
#include "storage/interface.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Block storage file-based:
//   data/blocks/blk00000.dat ... blkN.dat  (append-only, blk.dat style)
//   data/blocks/index.dat                  (hash -> {height, file, offset, size})
// ---------------------------------------------------------------------------
class CBlockStorage : public IStorage {
public:
    explicit CBlockStorage(const std::string& dataDir);

    bool WriteBlock(const CBlock& blk, int64_t height) override;
    bool ReadBlock(const uint256& hash, CBlock& blk) override;
    bool HasBlock(const uint256& hash) override;

    bool SaveChainState(const CCoinsView& view, int64_t height,
                        const uint256& tipHash, const std::vector<uint256>& byHeight) override;
    bool LoadChainState(CCoinsView& view, int64_t& height,
                        uint256& tipHash, std::vector<uint256>& byHeight) override;

    bool SavePeers(const std::vector<std::string>& addresses) override;
    std::vector<std::string> LoadPeers() override;

    // jumlah block tersimpan
    size_t BlockCount();

private:
    std::string dir;
    std::string blocksDir;
    std::map<uint256, std::tuple<int64_t, int, int64_t, int64_t>> index; // hash -> (height,file,offset,size)
    bool loaded = false;

    void LoadIndex();
    void SaveIndex();
    std::string BlockFilePath(int fileNum);
    int AppendToFile(const std::vector<uint8_t>& data); // returns file number
    bool ReadFromFile(int fileNum, int64_t offset, int64_t size, std::vector<uint8_t>& out);
};

} // namespace cdx
