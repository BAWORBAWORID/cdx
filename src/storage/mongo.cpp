#include "storage/mongo.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/md5.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <mutex>
#include <sstream>

// ---------------------------------------------------------------------------
// Minimal MongoDB client — cukup untuk peer registry:
//   - mongodb+srv:// (DNS SRV lookup) / mongodb://
//   - TLS via OpenSSL
//   - OP_MSG (opcode 2013)
//   - SCRAM-SHA-256 / SCRAM-SHA-1 auth (payload PLAINTEXT)
//   - ping / update(upsert) / find / delete
// Bukan konsensus storage — hanya peer discovery (spek CDX: MongoDB optional).
// ---------------------------------------------------------------------------

namespace cdx {

namespace {

// ---------------------------------------------------------------------------
// BSON encode (minimal)
// ---------------------------------------------------------------------------
class BsonDoc {
public:
    std::vector<uint8_t> b;
    BsonDoc() { b.resize(4, 0); } // int32 length placeholder

    void finish() {
        // terminator DULU, lalu length dihitung SETELAH terminator
        // (BSON: length termasuk terminator)
        b.push_back(0);
        uint32_t n = (uint32_t)b.size();
        b[0] = (uint8_t)(n & 0xff);
        b[1] = (uint8_t)((n >> 8) & 0xff);
        b[2] = (uint8_t)((n >> 16) & 0xff);
        b[3] = (uint8_t)((n >> 24) & 0xff);
    }

    void str(const std::string& k, const std::string& v) {
        b.push_back(0x02); key(k);
        int32_t len = (int32_t)v.size() + 1;
        addI32(len);
        b.insert(b.end(), v.begin(), v.end());
        b.push_back(0);
    }
    void i32(const std::string& k, int32_t v) { b.push_back(0x10); key(k); addI32(v); }
    void i64(const std::string& k, int64_t v) { b.push_back(0x12); key(k); addI64(v); }
    void boolean(const std::string& k, bool v) { b.push_back(0x08); key(k); b.push_back(v ? 1 : 0); }
    void null(const std::string& k) { b.push_back(0x0A); key(k); }
    void binary(const std::string& k, const std::vector<uint8_t>& v) {
        b.push_back(0x05); key(k);
        addI32((int32_t)v.size());
        b.push_back(0); // subtype
        b.insert(b.end(), v.begin(), v.end());
    }
    void doc(const std::string& k, BsonDoc d) {
        // salin + finish inner doc (length + terminator) sebelum disisipkan
        d.finish();
        b.push_back(0x03); key(k);
        b.insert(b.end(), d.b.begin(), d.b.end());
    }
    void arrDoc(const std::string& k, std::vector<BsonDoc> items) {
        b.push_back(0x04); key(k);
        BsonDoc arr;
        for (size_t i = 0; i < items.size(); ++i)
            arr.doc(std::to_string(i), items[i]);
        arr.finish();
        b.insert(b.end(), arr.b.begin(), arr.b.end());
    }

private:
    void key(const std::string& k) {
        b.insert(b.end(), k.begin(), k.end());
        b.push_back(0);
    }
    void addI32(int32_t v) {
        uint32_t u = (uint32_t)v;
        for (int i = 0; i < 4; ++i) b.push_back((uint8_t)((u >> (8 * i)) & 0xff));
    }
    void addI64(int64_t v) {
        uint64_t u = (uint64_t)v;
        for (int i = 0; i < 8; ++i) b.push_back((uint8_t)((u >> (8 * i)) & 0xff));
    }
};

// ---------------------------------------------------------------------------
// BSON decode (minimal — cukup untuk response)
// ---------------------------------------------------------------------------
struct BsonValue {
    uint8_t type = 0;
    std::string str;
    int64_t i64 = 0;
    bool boolean = false;
    std::vector<uint8_t> bytes;                                // binary payload
    std::vector<std::pair<std::string, BsonValue>> doc;        // doc / array
};

static bool ParseBson(const uint8_t* p, size_t len,
                      std::vector<std::pair<std::string, BsonValue>>& out) {
    if (len < 5) return false;
    uint32_t docLen;
    std::memcpy(&docLen, p, 4);
    if (docLen < 5 || docLen > len) return false;
    size_t pos = 4;
    while (pos + 1 < docLen) {
        uint8_t type = p[pos++];
        if (type == 0) break;
        // cstring key
        size_t keyStart = pos;
        while (pos < docLen && p[pos] != 0) ++pos;
        if (pos >= docLen) return false;
        std::string k((const char*)p + keyStart, pos - keyStart);
        ++pos;
        BsonValue v;
        v.type = type;
        switch (type) {
            case 0x01: { // double
                if (pos + 8 > docLen) return false;
                double d; std::memcpy(&d, p + pos, 8); v.i64 = (int64_t)d; pos += 8;
                break;
            }
            case 0x02: { // string
                if (pos + 4 > docLen) return false;
                int32_t sl; std::memcpy(&sl, p + pos, 4); pos += 4;
                if (sl < 0 || (size_t)sl > docLen - pos) return false;
                v.str.assign((const char*)p + pos, (size_t)sl > 0 ? (size_t)sl - 1 : 0);
                pos += (size_t)sl;
                break;
            }
            case 0x03: case 0x04: { // doc / array
                if (pos + 4 > docLen) return false;
                uint32_t subLen; std::memcpy(&subLen, p + pos, 4);
                if (subLen < 5 || (size_t)subLen > docLen - pos) return false;
                ParseBson(p + pos, subLen, v.doc);
                pos += subLen;
                break;
            }
            case 0x05: { // binary
                if (pos + 5 > docLen) return false;
                int32_t bl; std::memcpy(&bl, p + pos, 4); pos += 4;
                uint8_t subtype = p[pos++];
                (void)subtype;
                if (bl < 0 || (size_t)bl > docLen - pos) return false;
                v.bytes.assign(p + pos, p + pos + bl);
                pos += (size_t)bl;
                break;
            }
            case 0x07: { pos += 12; break; }          // objectid
            case 0x08: { v.boolean = (p[pos] != 0); pos += 1; break; }
            case 0x09: case 0x11: {                    // datetime / timestamp
                if (pos + 8 > docLen) return false;
                std::memcpy(&v.i64, p + pos, 8); pos += 8;
                break;
            }
            case 0x0A: { break; }                      // null
            case 0x10: {                                // int32
                if (pos + 4 > docLen) return false;
                int32_t x; std::memcpy(&x, p + pos, 4); v.i64 = x; pos += 4;
                break;
            }
            case 0x12: {                                // int64
                if (pos + 8 > docLen) return false;
                std::memcpy(&v.i64, p + pos, 8); pos += 8;
                break;
            }
            default: { return false; }
        }
        out.push_back({k, std::move(v)});
    }
    return true;
}

static const BsonValue* FindField(const std::vector<std::pair<std::string, BsonValue>>& doc,
                                  const std::string& name) {
    for (const auto& e : doc)
        if (e.first == name) return &e.second;
    return nullptr;
}

// ---------------------------------------------------------------------------
// Base64 (OpenSSL BIO)
// ---------------------------------------------------------------------------
static std::string B64Encode(const uint8_t* d, size_t n) {
    std::string out(4 * ((n + 2) / 3), '\0');
    int got = EVP_EncodeBlock((uint8_t*)out.data(), d, (int)n);
    out.resize(got > 0 ? (size_t)got : 0);
    return out;
}
static std::vector<uint8_t> B64Decode(const std::string& s) {
    if (s.empty()) return {};
    BIO* mem = BIO_new_mem_buf(s.data(), (int)s.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    mem = BIO_push(b64, mem);
    std::vector<uint8_t> out(s.size());
    int got = BIO_read(b64, out.data(), (int)out.size());
    BIO_free_all(mem);
    if (got < 0) return {};
    out.resize((size_t)got);
    return out;
}

// ---------------------------------------------------------------------------
// DNS SRV lookup (raw UDP query — _mongodb._tcp.<host>)
// ---------------------------------------------------------------------------
// query SRV ke satu nameserver; return true jika ada jawaban
static bool DnsSrvQueryOne(const std::string& ns, const std::string& domain,
                           std::vector<std::pair<std::string, uint16_t>>& out) {
    struct sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    if (inet_pton(AF_INET, ns.c_str(), &sa.sin_addr) != 1) return false;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct timeval tv = {4, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    std::vector<uint8_t> q;
    uint16_t id = (uint16_t)(rand() & 0xffff);
    q.push_back((uint8_t)(id >> 8)); q.push_back((uint8_t)(id & 0xff));
    q.push_back(0x01); q.push_back(0x00); // RD
    q.push_back(0x00); q.push_back(0x01); // QDCOUNT
    q.push_back(0x00); q.push_back(0x00); // ANCOUNT
    q.push_back(0x00); q.push_back(0x00); // NSCOUNT
    q.push_back(0x00); q.push_back(0x00); // ARCOUNT
    {
        std::stringstream ss(domain);
        std::string label;
        while (std::getline(ss, label, '.')) {
            q.push_back((uint8_t)label.size());
            q.insert(q.end(), label.begin(), label.end());
        }
        q.push_back(0);
    }
    q.push_back(0x00); q.push_back(0x21); // QTYPE SRV
    q.push_back(0x00); q.push_back(0x01); // QCLASS IN

    if (sendto(fd, q.data(), q.size(), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(fd);
        return false;
    }
    uint8_t resp[4096];
    ssize_t n = recv(fd, resp, sizeof(resp), 0);
    close(fd);
    if (n < 12) return false;
    if ((resp[0] != (uint8_t)(id >> 8)) || (resp[1] != (uint8_t)(id & 0xff))) return false;
    uint16_t ancount = ((uint16_t)resp[6] << 8) | resp[7];
    size_t pos = 12;
    {
        while (pos < (size_t)n && resp[pos] != 0) pos += (size_t)resp[pos] + 1;
        pos += 5;
    }
    for (uint16_t i = 0; i < ancount && pos + 12 <= (size_t)n; ++i) {
        if (pos < (size_t)n && (resp[pos] & 0xC0) == 0xC0) pos += 2;
        else {
            while (pos < (size_t)n && resp[pos] != 0) pos += (size_t)resp[pos] + 1;
            ++pos;
        }
        if (pos + 10 > (size_t)n) break;
        uint16_t type = ((uint16_t)resp[pos] << 8) | resp[pos + 1];
        uint16_t rdlen = ((uint16_t)resp[pos + 8] << 8) | resp[pos + 9];
        pos += 10;
        if (type == 33 && rdlen >= 6 && pos + rdlen <= (size_t)n) {
            uint16_t port = ((uint16_t)resp[pos + 4] << 8) | resp[pos + 5];
            size_t tp = pos + 6;
            std::string host;
            while (tp < (size_t)n && resp[tp] != 0) {
                if ((resp[tp] & 0xC0) == 0xC0) { tp += 2; break; }
                uint8_t l = resp[tp++];
                if (tp + l > (size_t)n) break;
                if (!host.empty()) host += ".";
                host.append((const char*)resp + tp, l);
                tp += l;
            }
            // strip trailing dot (FQDN absolut dari SRV)
            while (!host.empty() && host.back() == '.') host.pop_back();
            if (!host.empty()) out.push_back({host, port});
        }
        pos += rdlen;
    }
    return !out.empty();
}

static bool DnsSrvLookup(const std::string& domain,
                         std::vector<std::pair<std::string, uint16_t>>& out) {
    // kumpulkan SEMUA nameserver dari resolv.conf (jangan hanya yang pertama —
    // di container PaaS nameserver pertama bisa internal/blocked)
    std::vector<std::string> nss;
    {
        std::ifstream f("/etc/resolv.conf");
        std::string line;
        while (std::getline(f, line)) {
            if (line.rfind("nameserver", 0) == 0) {
                std::istringstream iss(line);
                std::string kw, ip;
                iss >> kw >> ip;
                if (!ip.empty()) nss.push_back(ip);
            }
        }
    }
    // fallback resolver publik
    nss.push_back("8.8.8.8");
    nss.push_back("1.1.1.1");

    for (const auto& ns : nss) {
        std::vector<std::pair<std::string, uint16_t>> tmp;
        if (DnsSrvQueryOne(ns, domain, tmp)) {
            out = std::move(tmp);
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// TLS socket
// ---------------------------------------------------------------------------
class TlsSocket {
public:
    TlsSocket() = default;
    ~TlsSocket() { Close(); }
    TlsSocket(const TlsSocket&) = delete;
    TlsSocket& operator=(const TlsSocket&) = delete;

    bool Connect(const std::string& host, uint16_t port, std::string& err) {
        struct addrinfo hints;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo* res = nullptr;
        std::string portStr = std::to_string(port);
        if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) {
            err = "resolve failed: " + host;
            return false;
        }
        int fd = -1;
        for (struct addrinfo* p = res; p; p = p->ai_next) {
            fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (fd < 0) continue;
            if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
            close(fd);
            fd = -1;
        }
        freeaddrinfo(res);
        if (fd < 0) {
            err = "connect failed: " + host + ":" + portStr;
            return false;
        }
        struct timeval tv = {30, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        ctx_ = SSL_CTX_new(TLS_client_method());
        if (!ctx_) { close(fd); err = "ssl ctx failed"; return false; }
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_default_verify_paths(ctx_);
        ssl_ = SSL_new(ctx_);
        if (!ssl_) { close(fd); err = "ssl new failed"; return false; }
        SSL_set_fd(ssl_, fd);
        SSL_set_tlsext_host_name(ssl_, host.c_str());
        if (SSL_connect(ssl_) != 1) {
            unsigned long e = ERR_get_error();
            char ebuf[256];
            ERR_error_string_n(e, ebuf, sizeof(ebuf));
            err = "TLS handshake failed: " + std::string(ebuf);
            Close();
            return false;
        }
        fd_ = fd;
        return true;
    }

    void Close() {
        if (ssl_) { SSL_shutdown(ssl_); SSL_free(ssl_); ssl_ = nullptr; }
        if (ctx_) { SSL_CTX_free(ctx_); ctx_ = nullptr; }
        if (fd_ >= 0) { close(fd_); fd_ = -1; }
    }

    bool WriteAll(const uint8_t* data, size_t len) {
        size_t sent = 0;
        while (sent < len) {
            int n = SSL_write(ssl_, data + sent, (int)(len - sent));
            if (n <= 0) return false;
            sent += (size_t)n;
        }
        return true;
    }

    bool ReadExact(uint8_t* data, size_t len) {
        size_t got = 0;
        while (got < len) {
            int n = SSL_read(ssl_, data + got, (int)(len - got));
            if (n <= 0) {
                int e = SSL_get_error(ssl_, n);
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                    struct pollfd pf = {fd_, POLLIN, 0};
                    poll(&pf, 1, 5000);
                    continue;
                }
                return false;
            }
            got += (size_t)n;
        }
        return true;
    }

private:
    int fd_ = -1;
    SSL_CTX* ctx_ = nullptr;
    SSL* ssl_ = nullptr;
};

// ---------------------------------------------------------------------------
// OP_MSG framing
// ---------------------------------------------------------------------------
static std::vector<uint8_t> BuildOpMsg(int32_t requestId, const BsonDoc& body) {
    std::vector<uint8_t> out;
    auto push32 = [&](int32_t v) {
        uint32_t u = (uint32_t)v;
        for (int i = 0; i < 4; ++i) out.push_back((uint8_t)((u >> (8 * i)) & 0xff));
    };
    push32(0);          // messageLength (patch nanti)
    push32(requestId);  // requestID
    push32(0);          // responseTo
    push32(2013);       // opCode OP_MSG
    push32(0);          // flagBits
    out.push_back(0);   // section kind 0 = single BSON
    out.insert(out.end(), body.b.begin(), body.b.end());
    uint32_t len = (uint32_t)out.size();
    out[0] = (uint8_t)(len & 0xff);
    out[1] = (uint8_t)((len >> 8) & 0xff);
    out[2] = (uint8_t)((len >> 16) & 0xff);
    out[3] = (uint8_t)((len >> 24) & 0xff);
    return out;
}

// ---------------------------------------------------------------------------
// SCRAM helpers
// ---------------------------------------------------------------------------
// password material untuk SCRAM-SHA-1: hex(md5(user ":mongo:" password))
static std::string ScramPasswordDigest(const std::string& user, const std::string& pass) {
    std::string raw = user + ":mongo:" + pass;
    unsigned char md[16];
    MD5((const unsigned char*)raw.data(), raw.size(), md);
    char hex[33];
    for (int i = 0; i < 16; ++i) std::sprintf(hex + i * 2, "%02x", md[i]);
    return hex;
}

} // namespace

// ---------------------------------------------------------------------------
// CMongoClient impl
// ---------------------------------------------------------------------------
struct CMongoClient::Impl {
    TlsSocket sock;
    std::string db = "cdx";          // database untuk collection registry
    std::string authSource = "admin";
    int32_t requestId = 1;

    bool Command(const BsonDoc& body, std::vector<std::pair<std::string, BsonValue>>& reply,
                 std::string& err) {
        auto frame = BuildOpMsg(requestId++, body);
        if (!sock.WriteAll(frame.data(), frame.size())) {
            err = "write failed";
            return false;
        }
        uint8_t hdr[16];
        if (!sock.ReadExact(hdr, 16)) { err = "read header failed"; return false; }
        int32_t msgLen;
        std::memcpy(&msgLen, hdr, 4);
        if (msgLen < 16 || msgLen > 16 * 1024 * 1024) { err = "bad message length"; return false; }
        std::vector<uint8_t> rest((size_t)msgLen - 16);
        if (!sock.ReadExact(rest.data(), rest.size())) { err = "read body failed"; return false; }
        if (rest.size() < 5) { err = "short body"; return false; }
        uint32_t flagBits;
        std::memcpy(&flagBits, rest.data(), 4);
        (void)flagBits;
        if (rest[4] != 0) { err = "unsupported section"; return false; }
        std::vector<std::pair<std::string, BsonValue>> doc;
        if (!ParseBson(rest.data() + 5, rest.size() - 5, doc)) { err = "bson parse failed"; return false; }
        reply = std::move(doc);
        const BsonValue* ok = FindField(reply, "ok");
        if (!ok) { err = "no ok field"; return false; }
        if (ok->i64 != 1) {
            const BsonValue* em = FindField(reply, "errmsg");
            err = em ? em->str : "command failed";
            return false;
        }
        return true;
    }

    // jalankan SCRAM dengan mekanisme tertentu; payload plaintext (bukan base64!)
    bool ScramAuth(const std::string& user, const std::string& pass,
                   const std::string& mechanism, std::string& err) {
        const EVP_MD* digest = EVP_sha256();
        int dlen = 32;
        std::string passwordData = pass; // SCRAM-SHA-256: password langsung
        if (mechanism == "SCRAM-SHA-1") {
            digest = EVP_sha1();
            dlen = 20;
            passwordData = ScramPasswordDigest(user, pass); // md5(user:mongo:pass) hex
        }

        // nonce (random hex)
        std::string nonce;
        {
            uint8_t rnd[18];
            RAND_bytes(rnd, sizeof(rnd));
            char hex[37];
            for (int i = 0; i < 18; ++i) std::sprintf(hex + i * 2, "%02x", rnd[i]);
            nonce = hex;
        }
        std::string cfm = "n,,n=" + user + ",r=" + nonce;          // client-first
        std::string cfmBare = "n=" + user + ",r=" + nonce;         // client-first-bare

        int64_t conversationId = 0;
        std::string serverFirst;
        {
            BsonDoc sasl;
            sasl.i32("saslStart", 1);
            sasl.str("mechanism", mechanism);
            // payload = PLAINTEXT client-first (bukan base64)
            sasl.binary("payload", std::vector<uint8_t>(cfm.begin(), cfm.end()));
            BsonDoc opts;
            opts.boolean("skipEmptyExchange", true);
            sasl.doc("options", opts);
            sasl.str("$db", authSource);
            sasl.finish();
            std::vector<std::pair<std::string, BsonValue>> reply;
            std::string serr;
            if (!Command(sasl, reply, serr)) { err = "saslStart failed: " + serr; return false; }
            const BsonValue* cid = FindField(reply, "conversationId");
            if (cid) conversationId = cid->i64;
            const BsonValue* pl = FindField(reply, "payload");
            if (!pl || pl->bytes.empty()) { err = "no sasl payload"; return false; }
            serverFirst.assign(pl->bytes.begin(), pl->bytes.end());
        }
        // parse server-first: r=<nonce2>,s=<saltB64>,i=<iter>
        std::string rv, sv, iv;
        {
            std::stringstream ss(serverFirst);
            std::string part;
            while (std::getline(ss, part, ',')) {
                if (part.rfind("r=", 0) == 0) rv = part.substr(2);
                else if (part.rfind("s=", 0) == 0) sv = part.substr(2);
                else if (part.rfind("i=", 0) == 0) iv = part.substr(2);
            }
        }
        if (rv.empty() || sv.empty() || iv.empty()) { err = "bad server-first"; return false; }
        int iterations = std::atoi(iv.c_str());
        auto salt = B64Decode(sv);
        if (salt.empty() || iterations <= 0) { err = "bad salt/iterations"; return false; }

        std::string cfWithoutProof = "c=biws,r=" + rv;
        unsigned char salted[32];
        if (PKCS5_PBKDF2_HMAC(passwordData.c_str(), (int)passwordData.size(),
                              salt.data(), (int)salt.size(), iterations, digest,
                              dlen, salted) != 1) {
            err = "pbkdf2 failed";
            return false;
        }
        unsigned char clientKey[32];
        unsigned int ckLen = 0;
        HMAC(digest, salted, dlen, (const unsigned char*)"Client Key", 10, clientKey, &ckLen);
        unsigned char storedKey[32];
        unsigned int skLen = 0;
        EVP_Digest(clientKey, ckLen, storedKey, &skLen, digest, nullptr);
        std::string authMessage = cfmBare + "," + serverFirst + "," + cfWithoutProof;
        unsigned char clientSig[32];
        unsigned int csLen = 0;
        HMAC(digest, storedKey, skLen, (const unsigned char*)authMessage.data(),
             authMessage.size(), clientSig, &csLen);
        unsigned char proof[32];
        for (int i = 0; i < (int)ckLen; ++i) proof[i] = clientKey[i] ^ clientSig[i];
        std::string cfmFull = cfWithoutProof + ",p=" + B64Encode(proof, ckLen);

        {
            BsonDoc cont;
            cont.i32("saslContinue", 1);
            cont.i64("conversationId", conversationId);
            cont.binary("payload", std::vector<uint8_t>(cfmFull.begin(), cfmFull.end()));
            cont.str("$db", authSource);
            cont.finish();
            std::vector<std::pair<std::string, BsonValue>> reply;
            std::string cerr;
            if (!Command(cont, reply, cerr)) { err = "saslContinue failed: " + cerr; return false; }
        }
        return true;
    }
};

CMongoClient::CMongoClient() : p_(new Impl) {}
CMongoClient::~CMongoClient() { Disconnect(); delete p_; }

void CMongoClient::Disconnect() {
    p_->sock.Close();
    connected_ = false;
}

bool CMongoClient::Connect(const std::string& uri, std::string& err) {
    Disconnect();
    std::string u = uri;
    bool useSrv = false;
    if (u.rfind("mongodb+srv://", 0) == 0) { useSrv = true; u = u.substr(14); }
    else if (u.rfind("mongodb://", 0) == 0) { u = u.substr(10); }
    else { err = "unsupported uri scheme"; return false; }

    std::string user, pass, host, dbPath;
    uint16_t port = 27017;
    size_t at = u.rfind('@');
    if (at != std::string::npos) {
        std::string cred = u.substr(0, at);
        u = u.substr(at + 1);
        size_t colon = cred.find(':');
        if (colon != std::string::npos) {
            user = cred.substr(0, colon);
            pass = cred.substr(colon + 1);
        } else {
            user = cred;
        }
    }
    size_t qm = u.find('?');
    std::string params;
    if (qm != std::string::npos) {
        params = u.substr(qm + 1);
        u = u.substr(0, qm);
    }
    size_t slash = u.find('/');
    if (slash != std::string::npos) {
        dbPath = u.substr(slash + 1);
        u = u.substr(0, slash);
    }
    size_t hcolon = u.rfind(':');
    if (hcolon != std::string::npos && !useSrv) {
        host = u.substr(0, hcolon);
        port = (uint16_t)std::atoi(u.substr(hcolon + 1).c_str());
    } else {
        host = u;
    }
    {
        std::stringstream ss(params);
        std::string kv;
        while (std::getline(ss, kv, '&')) {
            if (kv.rfind("authSource=", 0) == 0) p_->authSource = kv.substr(11);
        }
    }
    if (!dbPath.empty()) p_->db = dbPath;
    if (user.empty() || pass.empty()) { err = "mongo uri must include user:pass"; return false; }

    std::vector<std::pair<std::string, uint16_t>> targets;
    if (useSrv) {
        std::string domain = "_mongodb._tcp." + host;
        if (!DnsSrvLookup(domain, targets) || targets.empty()) {
            err = "SRV lookup failed for " + domain;
            return false;
        }
    } else {
        targets.push_back({host, port});
    }

    bool ok = false;
    for (const auto& t : targets) {
        std::string terr;
        if (!p_->sock.Connect(t.first, t.second, terr)) {
            err = terr;
            continue;
        }
        ok = true;
        break;
    }
    if (!ok) {
        err = "no reachable host: " + err;
        return false;
    }

    // handshake: hello (baca `primary` untuk replica set — tulis harus ke primary)
    std::string primaryAddr;
    {
        BsonDoc hello;
        hello.i32("hello", 1);
        BsonDoc mechs;
        mechs.str("db", p_->authSource);
        mechs.str("user", user);
        hello.doc("saslSupportedMechs", mechs);
        hello.str("$db", p_->authSource);
        hello.finish();
        std::vector<std::pair<std::string, BsonValue>> reply;
        std::string herr;
        if (!p_->Command(hello, reply, herr)) { err = "hello failed: " + herr; Disconnect(); return false; }
        const BsonValue* prim = FindField(reply, "primary");
        if (prim && !prim->str.empty()) primaryAddr = prim->str;
    }
    // kalau host ini bukan primary (replica set), reconnect ke primary
    if (!primaryAddr.empty()) {
        size_t pc = primaryAddr.rfind(':');
        if (pc != std::string::npos) {
            std::string ph = primaryAddr.substr(0, pc);
            uint16_t pp = (uint16_t)std::atoi(primaryAddr.substr(pc + 1).c_str());
            // bandingkan dengan host yang SEDANG kita pakai (targets[0])
            bool same = !targets.empty() && targets[0].first == ph && targets[0].second == pp;
            if (!same && pp != 0) {
                std::printf("[mongo] switching to primary %s\n", primaryAddr.c_str());
                p_->sock.Close();
                std::string terr;
                if (!p_->sock.Connect(ph, pp, terr)) {
                    err = "primary connect failed: " + terr;
                    Disconnect();
                    return false;
                }
                // hello ulang di primary
                BsonDoc hello;
                hello.i32("hello", 1);
                hello.str("$db", p_->authSource);
                hello.finish();
                std::vector<std::pair<std::string, BsonValue>> reply;
                std::string herr;
                if (!p_->Command(hello, reply, herr)) { err = "hello(primary) failed: " + herr; Disconnect(); return false; }
            }
        }
    }

    // auth: coba SCRAM-SHA-256 dulu, fallback SCRAM-SHA-1 (banyak cluster lama
    // hanya mendukung SHA-1, dan password pakai md5(user:mongo:pass))
    if (!p_->ScramAuth(user, pass, "SCRAM-SHA-256", err)) {
        std::string err1 = err;
        if (!p_->ScramAuth(user, pass, "SCRAM-SHA-1", err)) {
            err = "auth failed (SHA-256: " + err1 + "; SHA-1: " + err + ")";
            Disconnect();
            return false;
        }
        std::printf("[mongo] auth via SCRAM-SHA-1 (fallback)\n");
    }

    // ping ("check mongo")
    {
        BsonDoc ping;
        ping.i32("ping", 1);
        ping.str("$db", p_->authSource);
        ping.finish();
        std::vector<std::pair<std::string, BsonValue>> reply;
        std::string perr;
        if (!p_->Command(ping, reply, perr)) { err = "ping failed: " + perr; Disconnect(); return false; }
    }

    connected_ = true;
    return true;
}

bool CMongoClient::Ping(std::string& err) {
    if (!connected_) { err = "not connected"; return false; }
    BsonDoc ping;
    ping.i32("ping", 1);
    ping.str("$db", p_->authSource);
    ping.finish();
    std::vector<std::pair<std::string, BsonValue>> reply;
    return p_->Command(ping, reply, err);
}

bool CMongoClient::UpsertPeer(const std::string& network, const std::string& addr,
                              int64_t lastSeen, std::string& err) {
    if (!connected_) { err = "not connected"; return false; }
    BsonDoc cmd;
    cmd.str("update", "peers");
    BsonDoc q;
    q.str("_id", network + ":" + addr);
    BsonDoc set;
    set.str("addr", addr);
    set.str("network", network);
    set.i64("lastSeen", lastSeen);
    BsonDoc u;
    u.doc("$set", set);
    BsonDoc upd;
    upd.doc("q", q);
    upd.doc("u", u);
    upd.boolean("upsert", true);
    cmd.arrDoc("updates", {upd});
    cmd.boolean("ordered", true);
    cmd.str("$db", p_->db);
    cmd.finish();
    std::vector<std::pair<std::string, BsonValue>> reply;
    return p_->Command(cmd, reply, err);
}

bool CMongoClient::FetchPeers(const std::string& network, const std::string& excludeAddr,
                              std::vector<MongoPeer>& out, std::string& err) {
    out.clear();
    if (!connected_) { err = "not connected"; return false; }
    BsonDoc cmd;
    cmd.str("find", "peers");
    BsonDoc filter;
    filter.str("network", network);
    if (!excludeAddr.empty()) {
        BsonDoc ne;
        ne.str("$ne", excludeAddr);
        filter.doc("addr", ne);
    }
    cmd.doc("filter", filter);
    BsonDoc sort;
    sort.i32("lastSeen", -1);
    cmd.doc("sort", sort);
    cmd.i32("limit", 100);
    BsonDoc proj;
    proj.i32("addr", 1);
    proj.i32("network", 1);
    proj.i32("lastSeen", 1);
    cmd.doc("projection", proj);
    cmd.str("$db", p_->db);
    cmd.finish();
    std::vector<std::pair<std::string, BsonValue>> reply;
    if (!p_->Command(cmd, reply, err)) return false;
    const BsonValue* cursor = FindField(reply, "cursor");
    if (!cursor) { err = "no cursor"; return false; }
    const BsonValue* firstBatch = FindField(cursor->doc, "firstBatch");
    if (!firstBatch) { err = "no firstBatch"; return false; }
    for (const auto& e : firstBatch->doc) {
        MongoPeer p;
        const BsonValue* addr = FindField(e.second.doc, "addr");
        const BsonValue* net = FindField(e.second.doc, "network");
        const BsonValue* ls = FindField(e.second.doc, "lastSeen");
        if (addr) p.addr = addr->str;
        if (net) p.network = net->str;
        if (ls) p.lastSeen = ls->i64;
        if (!p.addr.empty()) out.push_back(std::move(p));
    }
    return true;
}

bool CMongoClient::CleanupStale(const std::string& network, int64_t cutoff, std::string& err) {
    if (!connected_) { err = "not connected"; return false; }
    BsonDoc cmd;
    cmd.str("delete", "peers");
    BsonDoc q;
    q.str("network", network);
    BsonDoc lt;
    lt.i64("$lt", cutoff);
    q.doc("lastSeen", lt);
    BsonDoc del;
    del.doc("q", q);
    del.i32("limit", 0);
    cmd.arrDoc("deletes", {del});
    cmd.str("$db", p_->db);
    cmd.finish();
    std::vector<std::pair<std::string, BsonValue>> reply;
    return p_->Command(cmd, reply, err);
}

} // namespace cdx
