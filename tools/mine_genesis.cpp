// =============================================================================
// tools/mine_genesis.cpp — miner genesis CDX yang CEPAT dan RESUMABLE.
//
// Genesis mainnet CDX memakai target 0x1d00ffff (~4.3 miliar hash). Tool
// cdx-genesis memakai SHA256d via OpenSSL EVP (~0.7 MH/s) sehingga butuh
// ~100 menit. Tool ini:
//   * Membangun genesis block NYATA (merkle root dari coinbase yang sama
//     dengan cdx-genesis) dan mencari nonce yang valid.
//   * SHA-256 (algoritma standar FIPS 180-4) — diverifikasi terhadap OpenSSL
//     pada startup (test vector berbagai panjang).
//   * Precompute state SHA untuk 64 byte pertama header (nonce di byte 76-79),
//     sehingga tiap nonce hanya butuh 1 kompresi block + 1 hash SHA256 dari
//     hasilnya (bukan 3 kompresi).
//   * Multi-thread (atomic work counter — resume aman).
//   * Resumable: menyimpan progress ke file, sehingga bisa dijalankan dalam
//     beberapa sesi (tool runner membunuh proses background antar call).
//
// Penggunaan:
//   mine_genesis <network> [threads] [timestamp]
//   Hasil dicetak; progress di <network>-genesis.progress
//   Setelah selesai, hasil dimasukkan ke src/config/networks.cpp dan genesis
//   diverifikasi ulang oleh cdx-genesis (hash sama).
// =============================================================================
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>
#include <atomic>
#include <fstream>
#include <chrono>
#include <openssl/sha.h>

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4) — kompresi dasar.
// ---------------------------------------------------------------------------
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_compress(uint32_t h[8], const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) | ((uint32_t)p[i*4+2] << 8) | p[i*4+3];
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

// SHA-256 full (streaming) — untuk verifikasi & hash akhir.
static void sha256_full(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t off = 0;
    while (len - off >= 64) { sha256_compress(h, data + off); off += 64; }
    size_t rem = len - off;
    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, data + off, rem);
    buf[rem] = 0x80;
    uint64_t bitlen = (uint64_t)len * 8;
    size_t idx = rem + 1;
    size_t padlen = (idx <= 56) ? 64 : 128;
    for (int i = 0; i < 8; ++i) buf[padlen - 8 + i] = (uint8_t)(bitlen >> (56 - 8*i));
    for (size_t i = 0; i < padlen; i += 64) sha256_compress(h, buf + i);
    for (int i = 0; i < 8; ++i) {
        out[i*4]=(uint8_t)(h[i]>>24); out[i*4+1]=(uint8_t)(h[i]>>16);
        out[i*4+2]=(uint8_t)(h[i]>>8); out[i*4+3]=(uint8_t)h[i];
    }
}

static void sha256d_full(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t t[32];
    sha256_full(data, len, t);
    sha256_full(t, 32, out);
}

// ---------------------------------------------------------------------------
// Mining state: 64 byte pertama header FIXED → precompute; tiap nonce hanya
// memproses block kedua (16 byte + padding) + hash 32 byte hasil.
// ---------------------------------------------------------------------------
struct MiningState {
    uint32_t hState[8];     // state setelah 64 byte pertama header
    uint8_t  block2[64];    // block kedua header (64-79) + padding
    uint32_t hResult[8];    // IV untuk hash kedua
    uint8_t  outPad[64];    // block padding hash 32 byte
};

static void prepare(const uint8_t hdr[80], MiningState& s) {
    uint32_t iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(s.hState, iv, 32);
    sha256_compress(s.hState, hdr);   // block 1: 64 byte pertama header
    memset(s.block2, 0, 64);
    memcpy(s.block2, hdr + 64, 16);
    s.block2[16] = 0x80;
    uint64_t bitlen = 80 * 8;
    for (int i = 0; i < 8; ++i) s.block2[63 - i] = (uint8_t)(bitlen >> (8 * i));
    memset(s.outPad, 0, 64);
    s.outPad[32] = 0x80;
    uint64_t bitlen2 = 256;
    for (int i = 0; i < 8; ++i) s.outPad[63 - i] = (uint8_t)(bitlen2 >> (8 * i));
    memcpy(s.hResult, iv, 32);
}

static void mine_hash(MiningState& s, uint32_t nonce, uint8_t out[32]) {
    uint32_t h[8];
    memcpy(h, s.hState, sizeof(h));
    s.block2[12] = (uint8_t)(nonce);
    s.block2[13] = (uint8_t)(nonce >> 8);
    s.block2[14] = (uint8_t)(nonce >> 16);
    s.block2[15] = (uint8_t)(nonce >> 24);
    sha256_compress(h, s.block2);
    uint32_t h2[8];
    memcpy(h2, s.hResult, sizeof(h2));
    for (int i = 0; i < 8; ++i) {
        s.outPad[i*4]   = (uint8_t)(h[i] >> 24);
        s.outPad[i*4+1] = (uint8_t)(h[i] >> 16);
        s.outPad[i*4+2] = (uint8_t)(h[i] >> 8);
        s.outPad[i*4+3] = (uint8_t)h[i];
    }
    sha256_compress(h2, s.outPad);
    for (int i = 0; i < 8; ++i) {
        out[i*4]   = (uint8_t)(h2[i] >> 24);
        out[i*4+1] = (uint8_t)(h2[i] >> 16);
        out[i*4+2] = (uint8_t)(h2[i] >> 8);
        out[i*4+3] = (uint8_t)h2[i];
    }
}

// cek hash <= target. Node (CheckProofOfWork): hash uint256 di-set dari bytes
// via setBytesLE → byte 31 = MSB bilangan. target[] disusun MSB-first.
// Jadi bandingkan hash sebagai little-endian: word i (dari MSB) pakai bytes
// 31-4i .. 28-4i dibaca big-endian, lawan target[i].
static bool hash_le_target(const uint8_t hash[32], const uint32_t target[8]) {
    for (int i = 0; i < 8; ++i) {
        int b = 31 - 4 * i;
        uint32_t hw = ((uint32_t)hash[b] << 24) | ((uint32_t)hash[b-1] << 16) |
                      ((uint32_t)hash[b-2] << 8) | hash[b-3];
        if (hw < target[i]) return true;
        if (hw > target[i]) return false;
    }
    return true;
}

static std::string hex32(const uint8_t* b) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 32; ++i) { s.push_back(H[b[i] >> 4]); s.push_back(H[b[i] & 0xf]); }
    return s;
}

// hash display node (getHex): byte terbalik dari raw hash
static std::string hex32_display(const uint8_t* b) {
    uint8_t rev[32];
    for (int i = 0; i < 32; ++i) rev[i] = b[31 - i];
    return hex32(rev);
}

static void target_from_bits(uint32_t bits, uint32_t target[8]) {
    memset(target, 0, 32);
    int exp = (int)(bits >> 24);
    uint32_t mant = bits & 0x007fffff;
    if (exp <= 3) {
        target[0] = mant >> (8 * (3 - exp));
    } else {
        uint8_t t[32];
        memset(t, 0, 32);
        t[32 - exp]     = (uint8_t)(mant >> 16);
        t[32 - exp + 1] = (uint8_t)(mant >> 8);
        t[32 - exp + 2] = (uint8_t)mant;
        for (int i = 0; i < 8; ++i) {
            uint32_t w = ((uint32_t)t[i*4] << 24) | ((uint32_t)t[i*4+1] << 16) |
                         ((uint32_t)t[i*4+2] << 8) | t[i*4+3];
            target[i] = w;
        }
    }
}

// ---------------------------------------------------------------------------
// Bangun header genesis NYATA (sama dengan cdx-genesis / genesis.cpp):
//   version=1, prevHash=0, merkleRoot dari coinbase, timestamp, bits, nonce=0
// ---------------------------------------------------------------------------
struct GenesisParams {
    uint32_t ts;
    uint32_t bits;
    int64_t reward;
    std::string message;
};

// coinbase genesis (identik dengan src/blockchain/genesis.cpp):
//   scriptSig  = [len(message)][message]
//   scriptPubKey = OP_TRUE {0x51}
//   merkleRoot = txid (hanya 1 tx → ComputeMerkleRoot mengembalikan txid)
static void build_genesis_header(const GenesisParams& g, uint8_t hdr[80]) {
    std::vector<uint8_t> scriptSig;
    scriptSig.push_back((uint8_t)g.message.size());
    scriptSig.insert(scriptSig.end(), g.message.begin(), g.message.end());

    std::vector<uint8_t> tx;
    auto putU32 = [&](uint32_t v) { tx.push_back((uint8_t)v); tx.push_back((uint8_t)(v>>8));
                                    tx.push_back((uint8_t)(v>>16)); tx.push_back((uint8_t)(v>>24)); };
    auto putU64 = [&](uint64_t v) { for (int i = 0; i < 8; ++i) tx.push_back((uint8_t)(v >> (8*i))); };
    putU32(1);                       // version
    tx.push_back(1);                 // vin count
    for (int i = 0; i < 32; ++i) tx.push_back(0); // prev hash (0)
    putU32(0xffffffff);              // prev n
    tx.push_back((uint8_t)scriptSig.size()); // scriptSig len varint (pendek)
    tx.insert(tx.end(), scriptSig.begin(), scriptSig.end());
    putU32(0xffffffff);              // sequence
    tx.push_back(1);                 // vout count
    putU64((uint64_t)g.reward);      // value
    tx.push_back(1);                 // scriptPubKey len
    tx.push_back(0x51);              // OP_TRUE
    putU32(0);                       // locktime

    // TXID = SHA256d(serialized tx)
    uint8_t txid[32];
    sha256d_full(tx.data(), tx.size(), txid);

    // merkle root = txid (1 tx)
    uint8_t merkle[32];
    memcpy(merkle, txid, 32);

    // header: version(4 LE) prevHash(32)=0 merkleRoot(32) ts(4 LE) bits(4 LE) nonce(4 LE)
    memset(hdr, 0, 80);
    hdr[0] = 1; hdr[1] = 0; hdr[2] = 0; hdr[3] = 0;   // version = 1 (LE)
    memcpy(hdr + 4 + 32, merkle, 32); // merkleRoot; prevHash 0 sudah di memset
    hdr[68] = (uint8_t)g.ts; hdr[69] = (uint8_t)(g.ts >> 8);
    hdr[70] = (uint8_t)(g.ts >> 16); hdr[71] = (uint8_t)(g.ts >> 24);
    hdr[72] = (uint8_t)g.bits; hdr[73] = (uint8_t)(g.bits >> 8);
    hdr[74] = (uint8_t)(g.bits >> 16); hdr[75] = (uint8_t)(g.bits >> 24);
    // nonce = 0
}

int main(int argc, char** argv) {
    std::string network = argc > 1 ? argv[1] : "mainnet";
    int threads = argc > 2 ? std::atoi(argv[2]) : 2;
    if (threads < 1) threads = 1;

    // --- verifikasi SHA256 terhadap OpenSSL ---
    {
        bool ok = true;
        for (size_t n = 1; n <= 200; ++n) {
            uint8_t buf[256]; memset(buf, (int)n, n);
            uint8_t a[32], b[32], t[32];
            sha256_full(buf, n, a);
            SHA256(buf, n, b);
            if (memcmp(a, b, 32) != 0) ok = false;
            sha256d_full(buf, n, a);
            SHA256(buf, n, t); SHA256(t, 32, b);
            if (memcmp(a, b, 32) != 0) ok = false;
        }
        printf("SHA256 self-test vs OpenSSL: %s\n", ok ? "PASS" : "FAIL");
        if (!ok) return 1;
    }

    GenesisParams g;
    g.ts = 1717200000;
    g.bits = 0x1d00ffffu;
    if (network == "regtest") g.bits = 0x207fffffu;
    g.reward = 50LL * 100000000LL;
    g.message = "CDX Genesis - Codex Coin, 21,000,000 CDX, SHA-256d PoW, UTXO, P2P";
    if (argc > 3) g.ts = (uint32_t)std::atoll(argv[3]);

    // --- resume ---
    std::string progFile = network + "-genesis.progress";
    uint64_t start = 0;
    uint32_t tsNow = g.ts;
    {
        std::ifstream f(progFile);
        if (f.good()) {
            uint64_t tsFile, n;
            f >> tsFile >> n;
            tsNow = (uint32_t)tsFile;
            start = n;
            g.ts = tsNow;
            printf("resume: ts=%u from hash counter %llu\n", g.ts, (unsigned long long)start);
        }
    }

    uint8_t hdr[80];
    build_genesis_header(g, hdr);

    uint32_t target[8];
    target_from_bits(g.bits, target);
    printf("mining %s genesis... bits=0x%08x ts=%u threads=%d\n",
           network.c_str(), g.bits, g.ts, threads);
    printf("message: %s\n", g.message.c_str());

    MiningState ms;
    prepare(hdr, ms);

    // --- mining multi-thread: atomic work counter (resume aman) ---
    std::atomic<bool> found{false};
    std::atomic<uint32_t> foundNonce{0};
    std::atomic<uint64_t> counter{start};       // work counter global
    std::atomic<uint64_t> totalHashes{0};

    auto worker = [&]() {
        MiningState local = ms;
        uint8_t out[32];
        uint64_t cnt = 0;
        for (;;) {
            uint64_t n = counter.fetch_add(1, std::memory_order_relaxed);
            if (n > 0xFFFFFFFFull) return;
            if (found.load(std::memory_order_relaxed)) return;
            mine_hash(local, (uint32_t)n, out);
            ++cnt;
            if ((cnt & 0xfffff) == 0) {
                // savepoint jarang (setiap ~1M hash) agar I/O tidak membunuh hashrate
                totalHashes.fetch_add(0x100000, std::memory_order_relaxed);
                std::ofstream f(progFile);
                f << g.ts << " " << counter.load(std::memory_order_relaxed) << "\n";
            }
            if (hash_le_target(out, target)) {
                foundNonce = (uint32_t)n;
                found = true;
                return;
            }
        }
    };

    auto t0 = std::chrono::steady_clock::now();
    std::vector<std::thread> ths;
    for (int i = 0; i < threads; ++i) ths.emplace_back(worker);

    // progress reporter
    while (!found.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(20));
        uint64_t now = totalHashes.load();
        double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        double rate = secs > 0 ? (double)now / secs / 1e6 : 0;
        printf("  %.2f MH/s | %llu M total | elapsed %.0fs | counter %llu\n",
               rate, (unsigned long long)(now / 1000000), secs,
               (unsigned long long)counter.load());
        fflush(stdout);
        {
            std::ofstream f(progFile);
            f << g.ts << " " << counter.load(std::memory_order_relaxed) << "\n";
        }
    }
    for (auto& th : ths) if (th.joinable()) th.join();

    if (!found.load()) {
        printf("nonce space exhausted; increase timestamp and re-run\n");
        return 1;
    }
    uint32_t nonce = foundNonce.load();
    printf("\n=== NONCE FOUND: %u ===\n", nonce);
    printf("ts=%u bits=0x%08x nonce=%u\n", g.ts, g.bits, nonce);
    {
        std::ofstream f(progFile);
        f << g.ts << " " << nonce << "\n";
    }
    // hash akhir
    hdr[76] = (uint8_t)nonce; hdr[77] = (uint8_t)(nonce >> 8);
    hdr[78] = (uint8_t)(nonce >> 16); hdr[79] = (uint8_t)(nonce >> 24);
    uint8_t fin[32];
    sha256d_full(hdr, 80, fin);
    printf("blockhash (display): %s\n", hex32_display(fin).c_str());
    printf("(simpan hash ini sebagai genesisHashHex di src/config/networks.cpp)\n");
    return 0;
}
