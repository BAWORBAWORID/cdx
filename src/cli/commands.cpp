#include "cli/commands.h"
#include "config/networks.h"
#include "crypto/encoding.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <sstream>

namespace cdx {

static std::string Base64Encode(const std::string& in) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    unsigned int val = 0;
    int bits = -6;
    for (char c : in) {
        val = (val << 8) + (unsigned char)c;
        bits += 8;
        while (bits >= 0) {
            out.push_back(tbl[(val >> bits) & 0x3f]);
            bits -= 6;
        }
    }
    if (bits > -6) out.push_back(tbl[((val << 8) >> (bits + 8)) & 0x3f]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::string RpcCall(const CliConfig& cfg, const std::string& method,
                    const std::vector<std::string>& params, std::string& error) {
    const ChainParams& p = GetParams(cfg.network);
    int port = p.rpcPort;
    if (!cfg.rpcPort.empty()) {
        try { port = std::stoi(cfg.rpcPort); } catch (...) { error = "invalid -rpcport"; return ""; }
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { error = "cannot create socket"; return ""; }
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        error = "cannot connect to cdxd RPC (is the node running?)";
        close(fd);
        return "";
    }
    // build JSON
    std::string body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method + "\",\"params\":[";
    for (size_t i = 0; i < params.size(); ++i) {
        if (i) body += ",";
        body += "\"" + params[i] + "\"";
    }
    body += "]}";
    std::string auth = "Authorization: Basic " + Base64Encode(cfg.rpcUser + ":" + cfg.rpcPassword) + "\r\n";
    std::string http = "POST / HTTP/1.1\r\nHost: localhost\r\n" + auth +
                       "Content-Type: application/json\r\nContent-Length: " +
                       std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    // send
    size_t sent = 0;
    while (sent < http.size()) {
        ssize_t n = send(fd, http.data() + sent, http.size() - sent, 0);
        if (n <= 0) break;
        sent += (size_t)n;
    }
    // recv dengan timeout
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    std::string resp;
    char buf[8192];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, (size_t)n);
        if (resp.find("\r\n\r\n") != std::string::npos && resp.find("}") != std::string::npos) {
            // cukup: cek content-length
            break;
        }
    }
    close(fd);
    if (resp.empty()) { error = "no response from node"; return ""; }
    // ekstrak body JSON setelah header
    size_t bodyStart = resp.find("\r\n\r\n");
    if (bodyStart != std::string::npos) resp = resp.substr(bodyStart + 4);
    return resp;
}

static void PrintRpcResult(const std::string& json) {
    // ekstrak "result": ... dari respon JSON sederhana
    size_t pos = json.find("\"result\":");
    if (pos == std::string::npos) {
        // mungkin error
        std::cout << json << std::endl;
        return;
    }
    pos += 9;
    // skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
    // ambil hingga ",\"error\""
    size_t end = json.find(",\"error\"", pos);
    if (end == std::string::npos) end = json.size() - 1;
    std::string result = json.substr(pos, end - pos);
    // unquote
    if (result.size() >= 2 && result[0] == '"' && result[result.size() - 1] == '"') {
        result = result.substr(1, result.size() - 2);
    }
    std::cout << result << std::endl;
}

int RunCliCommand(const CliConfig& cfg, const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Usage: cdx-cli <command> [args...]" << std::endl;
        return 1;
    }
    const std::string& cmd = args[0];

    // --- blockchain ---
    if (cmd == "blockchain" && args.size() > 1 && args[1] == "info") {
        std::string e;
        auto r = RpcCall(cfg, "getblockchaininfo", {}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }
    if (cmd == "blockchain" && args.size() > 1 && args[1] == "height") {
        std::string e;
        auto r = RpcCall(cfg, "getblockcount", {}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }
    if (cmd == "blockchain" && args.size() > 1 && args[1] == "sync") {
        std::string e;
        auto r = RpcCall(cfg, "getblockchaininfo", {}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }
    if (cmd == "blockchain" && args.size() > 2 && args[1] == "getblock") {
        std::string e;
        auto r = RpcCall(cfg, "getblock", {args[2]}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }

    // --- wallet ---
    if (cmd == "wallet" && args.size() > 1 && args[1] == "getnewaddress") {
        std::string e;
        auto r = RpcCall(cfg, "getnewaddress", {}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }
    if (cmd == "wallet" && args.size() > 1 && args[1] == "balance") {
        std::string e;
        auto r = RpcCall(cfg, "getbalance", {}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }
    if (cmd == "wallet" && args.size() > 1 && args[1] == "history") {
        std::string e;
        auto r = RpcCall(cfg, "listtransactions", {}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }
    if (cmd == "wallet" && args.size() > 1 && args[1] == "listaddresses") {
        std::string e;
        auto r = RpcCall(cfg, "getaddresses", {}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }

    // --- send ---
    if (cmd == "send" && args.size() >= 3) {
        std::string e;
        auto r = RpcCall(cfg, "sendtoaddress", {args[1], args[2]}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }

    // --- mining ---
    if (cmd == "mining" && args.size() > 1 && args[1] == "status") {
        std::string e;
        auto r = RpcCall(cfg, "getmininginfo", {}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }
    if (cmd == "mining" && args.size() > 1 && args[1] == "start") {
        std::string e;
        auto r = RpcCall(cfg, "startmining", {}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }
    if (cmd == "mining" && args.size() > 1 && args[1] == "stop") {
        std::string e;
        auto r = RpcCall(cfg, "stopmining", {}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }
    if (cmd == "mining" && args.size() > 2 && args[1] == "setaddress") {
        std::string e;
        auto r = RpcCall(cfg, "setminingaddress", {args[2]}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }
    if (cmd == "mining" && args.size() > 1 && args[1] == "getaddress") {
        std::string e;
        auto r = RpcCall(cfg, "getminingaddress", {}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }

    // --- network ---
    if (cmd == "network" && args.size() > 1 && args[1] == "peers") {
        std::string e;
        auto r = RpcCall(cfg, "getpeerinfo", {}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }
    if (cmd == "network" && args.size() > 1 && args[1] == "info") {
        std::string e;
        auto r = RpcCall(cfg, "getnetworkinfo", {}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }
    if (cmd == "network" && args.size() > 1 && args[1] == "connect") {
        std::string e;
        auto r = RpcCall(cfg, "addnode", {args[2]}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }

    // --- mempool ---
    if (cmd == "mempool" || (cmd == "mempool" && args.size() > 1 && args[1] == "info")) {
        std::string e;
        auto r = RpcCall(cfg, "getmempoolinfo", {}, e);
        if (e.empty()) PrintRpcResult(r);
        else { std::cerr << e << std::endl; return 1; }
        return 0;
    }

    std::cout << "Unknown command: " << cmd << std::endl;
    return 1;
}

} // namespace cdx
