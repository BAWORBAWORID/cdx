#include "wallet/backup.h"
#include "crypto/encoding.h"
#include <fstream>
#include <filesystem>
#include <ctime>

namespace fs = std::filesystem;

namespace cdx {

std::string SaveBackupFile(const std::string& dataDir, const CWallet& wallet,
                           const std::string& password, std::string& error) {
    fs::create_directories(dataDir + "/wallets");
    std::string path = dataDir + "/wallets/cdx-wallet-backup.dat";
    try {
        auto backup = wallet.Backup(password);
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out.good()) {
            error = "cannot open backup file";
            return "";
        }
        out.write((const char*)backup.data(), (std::streamsize)backup.size());
        out.close();
        return path;
    } catch (const std::exception& e) {
        error = e.what();
        return "";
    }
}

CWallet LoadBackupFile(const std::string& path, const std::string& password, std::string& error) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in.good()) {
        error = "cannot open backup file";
        return CWallet();
    }
    std::streamsize size = in.tellg();
    in.seekg(0);
    std::vector<uint8_t> data((size_t)size);
    in.read((char*)data.data(), size);
    in.close();
    return CWallet::Restore(data, password, error);
}

} // namespace cdx
