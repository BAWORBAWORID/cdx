#pragma once
#include <atomic>
#include <cstdint>
#include <string>
#include <map>
#include <mutex>
#include <thread>
#include <functional>
#include <vector>
#include "config/networks.h"

namespace cdx {

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 over TCP — localhost only, authenticated.
// Raw RPC TIDAK boleh diekspos publik.
// ---------------------------------------------------------------------------

using RpcMethodFn = std::function<std::string(const std::vector<std::string>& params)>;

class CRpcServer {
public:
    CRpcServer(const ChainParams& params, const std::string& rpcUser, const std::string& rpcPassword);

    void Register(const std::string& name, RpcMethodFn fn);
    bool Start(std::string& error);
    void Stop();

    // jalankan satu permintaan JSON-RPC; mengembalikan respon JSON
    std::string HandleRequest(const std::string& requestBody, const std::string& authHeader);

private:
    const ChainParams& params;
    std::string rpcUser, rpcPassword;
    std::map<std::string, RpcMethodFn> methods;
    std::atomic<bool> running{false};
    std::thread acceptThread;
    int listenFd = -1;
    std::mutex mutex;

    void AcceptLoop();
    bool CheckAuth(const std::string& authHeader) const;
    std::string HandleRequestInner(const std::string& requestBody);
};

} // namespace cdx
