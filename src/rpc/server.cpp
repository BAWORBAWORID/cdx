#include "rpc/server.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>
#include <sstream>
#include <chrono>
#include <thread>
#include <atomic>

namespace cdx {

static std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

CRpcServer::CRpcServer(const ChainParams& params, const std::string& u, const std::string& p)
    : params(params), rpcUser(u), rpcPassword(p) {}

void CRpcServer::Register(const std::string& name, RpcMethodFn fn) {
    methods[name] = std::move(fn);
}

static void SetNonBlocking2(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

bool CRpcServer::Start(std::string& error) {
    if (running.load()) return true;
    listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd < 0) { error = "rpc: socket failed"; return false; }
    int opt = 1;
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // localhost only
    addr.sin_port = htons(params.rpcPort);
    if (bind(listenFd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        error = "rpc: cannot bind port " + std::to_string(params.rpcPort);
        close(listenFd);
        listenFd = -1;
        return false;
    }
    if (listen(listenFd, 8) != 0) {
        error = "rpc: cannot listen";
        close(listenFd);
        listenFd = -1;
        return false;
    }
    SetNonBlocking2(listenFd);
    running = true;
    acceptThread = std::thread([this]() { AcceptLoop(); });
    return true;
}

void CRpcServer::Stop() {
    running = false;
    if (listenFd >= 0) { close(listenFd); listenFd = -1; }
    if (acceptThread.joinable()) acceptThread.join();
}

void CRpcServer::AcceptLoop() {
    while (running.load()) {
        struct sockaddr_in clientAddr;
        socklen_t len = sizeof(clientAddr);
        int fd = accept(listenFd, (struct sockaddr*)&clientAddr, &len);
        if (fd < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        SetNonBlocking2(fd);
        // baca satu permintaan (dengan timeout)
        std::string request;
        std::string authHeader;
        {
            std::vector<uint8_t> buf(4096);
            int64_t deadline = (int64_t)time(nullptr) + 10;
            bool first = true;
            while ((int64_t)time(nullptr) < deadline) {
                struct pollfd pf = {fd, POLLIN, 0};
                int rc = poll(&pf, 1, 1000);
                if (rc <= 0) continue;
                ssize_t n = recv(fd, buf.data(), buf.size(), 0);
                if (n > 0) {
                    // parse header jika masih di awal
                    std::string chunk((char*)buf.data(), (size_t)n);
                    if (first) {
                        first = false;
                        // cari Authorization header
                        size_t authPos = chunk.find("Authorization:");
                        if (authPos != std::string::npos) {
                            size_t nl = chunk.find("\r\n", authPos);
                            if (nl == std::string::npos) nl = chunk.find("\n", authPos);
                            if (nl != std::string::npos) {
                                authHeader = chunk.substr(authPos + 14, nl - authPos - 14);
                                // trim
                                size_t s = authHeader.find_first_not_of(" \t");
                                size_t e = authHeader.find_last_not_of(" \t\r");
                                if (s != std::string::npos && e != std::string::npos)
                                    authHeader = authHeader.substr(s, e - s + 1);
                                else authHeader.clear();
                            }
                        }
                        // potong header, simpan body
                        size_t bodyStart = chunk.find("\r\n\r\n");
                        if (bodyStart == std::string::npos) bodyStart = chunk.find("\n\n");
                        if (bodyStart != std::string::npos) {
                            request = chunk.substr(bodyStart + 4);
                        } else {
                            // header belum selesai: simpan sementara
                            request = chunk;
                            continue;
                        }
                    } else {
                        request += chunk;
                    }
                    // content-length check
                    if (request.size() > 1024 * 1024) break;
                    if (request.find("\0", 0) != std::string::npos) break;
                    // cukup bila request tampak JSON lengkap (ada penutup })
                    if (request.find('}') != std::string::npos &&
                        (request.find("\r\n\r\n") != std::string::npos ||
                         chunk.find("\r\n\r\n") != std::string::npos ||
                         first == false)) {
                        break;
                    }
                } else if (n == 0) {
                    break;
                } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    break;
                }
            }
        }
        if (!request.empty()) {
            std::string response = HandleRequest(request, authHeader);
            std::string http = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                               "Content-Length: " + std::to_string(response.size()) +
                               "\r\nConnection: close\r\n\r\n" + response;
            size_t sent = 0;
            while (sent < http.size()) {
                ssize_t n = send(fd, http.data() + sent, http.size() - sent, MSG_NOSIGNAL);
                if (n > 0) sent += (size_t)n;
                else if (errno == EAGAIN) {
                    struct pollfd pf = {fd, POLLOUT, 0};
                    poll(&pf, 1, 2000);
                } else break;
            }
        }
        close(fd);
    }
}

bool CRpcServer::CheckAuth(const std::string& authHeader) const {
    if (rpcUser.empty()) return true; // no auth configured
    // Basic auth
    const std::string prefix = "Basic ";
    if (authHeader.rfind(prefix, 0) != 0) return false;
    std::string b64 = authHeader.substr(prefix.size());
    // decode base64
    auto decode = [](const std::string& in) -> std::string {
        static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int val[256];
        std::memset(val, -1, sizeof(val));
        for (int i = 0; i < 64; ++i) val[(uint8_t)tbl[i]] = i;
        std::string out;
        unsigned int acc = 0;
        int nbits = 0;
        for (char c : in) {
            if (c == '=') break;
            if (val[(uint8_t)c] < 0) continue;
            acc = (acc << 6) | (unsigned int)val[(uint8_t)c];
            nbits += 6;
            if (nbits >= 8) {
                nbits -= 8;
                out.push_back((char)((acc >> nbits) & 0xff));
            }
        }
        return out;
    };
    std::string decoded = decode(b64);
    std::string expected = rpcUser + ":" + rpcPassword;
    return decoded == expected;
}

std::string CRpcServer::HandleRequest(const std::string& requestBody, const std::string& authHeader) {
    if (!CheckAuth(authHeader)) {
        return "{\"error\":{\"code\":-32600,\"message\":\"unauthorized\"},\"id\":null}";
    }
    return HandleRequestInner(requestBody);
}

std::string CRpcServer::HandleRequestInner(const std::string& requestBody) {
    // parse JSON minimal: {"method":"...","params":[...],"id":N}
    std::string method;
    std::vector<std::string> params;
    std::string id = "null";
    std::string body = requestBody;
    // cari method
    auto findJsonStr = [&](const std::string& key) -> std::string {
        size_t pos = body.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        size_t colon = body.find(':', pos + key.size() + 2);
        if (colon == std::string::npos) return "";
        size_t start = body.find('"', colon + 1);
        if (start == std::string::npos) return "";
        size_t end = body.find('"', start + 1);
        if (end == std::string::npos) return "";
        std::string val = body.substr(start + 1, end - start - 1);
        // unescape sederhana
        std::string unescaped;
        for (size_t i = 0; i < val.size(); ++i) {
            if (val[i] == '\\' && i + 1 < val.size()) {
                ++i;
                if (val[i] == 'n') unescaped += '\n';
                else if (val[i] == 't') unescaped += '\t';
                else if (val[i] == '"') unescaped += '"';
                else if (val[i] == '\\') unescaped += '\\';
                else unescaped += val[i];
            } else {
                unescaped += val[i];
            }
        }
        return unescaped;
    };
    method = findJsonStr("method");
    // params: array of strings (kebanyakan method CLI mengambil string)
    {
        size_t pos = body.find("\"params\"");
        if (pos != std::string::npos) {
            size_t colon = body.find(':', pos + 7);
            if (colon != std::string::npos) {
                size_t start = body.find('[', colon);
                if (start != std::string::npos) {
                    size_t depth = 1;
                    size_t i = start + 1;
                    std::string cur;
                    bool inStr = false;
                    for (; i < body.size() && depth > 0; ++i) {
                        char c = body[i];
                        if (c == '"') {
                            if (inStr) { inStr = false; }
                            else { inStr = true; }
                            continue; // jangan sertakan tanda kutip
                        }
                        if (!inStr) {
                            if (c == '[') ++depth;
                            else if (c == ']') { --depth; if (depth == 0) break; }
                            else if (c == ',') { if (!cur.empty()) params.push_back(cur); cur.clear(); continue; }
                        }
                        cur += c;
                    }
                    if (!cur.empty()) params.push_back(cur);
                }
            }
        }
    }
    // id
    {
        size_t pos = body.find("\"id\"");
        if (pos != std::string::npos) {
            size_t colon = body.find(':', pos + 3);
            if (colon != std::string::npos) {
                size_t start = body.find_first_not_of(" \t", colon + 1);
                if (start != std::string::npos) {
                    size_t end = body.find_first_of(",}", start);
                    if (end != std::string::npos) {
                        id = body.substr(start, end - start);
                        // trim
                        size_t s = id.find_first_not_of(" \t");
                        size_t e = id.find_last_not_of(" \t");
                        if (s != std::string::npos && e != std::string::npos)
                            id = id.substr(s, e - s + 1);
                    }
                }
            }
        }
    }
    // quote id jika string
    if (id.empty() || id == "null" || id == "0" || id == "1" || id == "2" || id == "3" ||
        id == "4" || id == "5" || id == "6" || id == "7" || id == "8" || id == "9") {
        // keep as-is
    } else if (id[0] != '"' && id[0] != '{' && id[0] != '[') {
        id = "\"" + JsonEscape(id) + "\"";
    }

    auto it = methods.find(method);
    if (it == methods.end()) {
        return "{\"result\":null,\"error\":{\"code\":-32601,\"message\":\"method not found: " +
               JsonEscape(method) + "\"},\"id\":" + id + "}";
    }
    std::string result;
    try {
        result = it->second(params);
    } catch (const std::exception& e) {
        return "{\"result\":null,\"error\":{\"code\":-32603,\"message\":\"" + JsonEscape(e.what()) +
               "\"},\"id\":" + id + "}";
    }
    return "{\"result\":" + result + ",\"error\":null,\"id\":" + id + "}";
}

} // namespace cdx
