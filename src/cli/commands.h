#pragma once
#include <string>
#include <vector>

namespace cdx {

// ---------------------------------------------------------------------------
// cdx-cli — client RPC ke node lokal.
// ---------------------------------------------------------------------------

struct CliConfig {
    std::string network = "mainnet";
    std::string rpcUser = "cdx";
    std::string rpcPassword = "cdx";
    std::string dataDir = "data";
    // override port RPC (kosong = default dari network params)
    std::string rpcPort = "";
};

// jalankan perintah CLI; return code
int RunCliCommand(const CliConfig& cfg, const std::vector<std::string>& args);

// helper RPC call (HTTP POST ke localhost)
std::string RpcCall(const CliConfig& cfg, const std::string& method,
                    const std::vector<std::string>& params, std::string& error);

} // namespace cdx
