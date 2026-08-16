#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include "config/networks.h"
#include "blockchain/genesis.h"
#include "blockchain/merkle.h"
#include "consensus/difficulty.h"
#include "transaction/serializer.h"
#include "crypto/hash.h"
#include "crypto/encoding.h"

using namespace cdx;

// ---------------------------------------------------------------------------
// cdx-genesis — tool untuk membuat & mining genesis block CDX.
//   cdx-genesis mainnet|testnet|regtest [timestamp] [message]
// Output: hash genesis + parameter untuk di-embed di config.
// ---------------------------------------------------------------------------

int main(int argc, char** argv) {
    std::string network = argc > 1 ? argv[1] : "mainnet";
    const ChainParams& params = GetParams(network);

    uint32_t ts = 1717200000;
    if (argc > 2) ts = (uint32_t)std::atoll(argv[2]);

    std::string message = GetGenesisMessage();
    if (argc > 3) message = argv[3];

    std::printf("Mining CDX %s genesis block...\n", network.c_str());
    std::printf("  bits: 0x%08x\n", params.minDifficultyBits);
    std::printf("  reward: %lld base units (%lld CDX)\n",
                (long long)INITIAL_BLOCK_REWARD, (long long)(INITIAL_BLOCK_REWARD / COIN));
    std::printf("  timestamp: %u\n", ts);
    std::printf("  message: %s\n", message.c_str());

    uint256 target = TargetFromBits(params.minDifficultyBits);
    std::printf("  target: %s\n", target.getHex().c_str());

    CBlock genesis = CreateGenesisBlock(params.minDifficultyBits, INITIAL_BLOCK_REWARD, ts, message, 0);
    auto headerSer = SerializeBlockHeader(genesis.header);
    uint8_t hdr[80];
    std::memcpy(hdr, headerSer.data(), 80);

    uint32_t nonce = 0;
    bool found = false;
    uint256 hash;
    while (true) {
        uint8_t b[4];
        WriteU32LE(b, nonce);
        hdr[76] = b[0]; hdr[77] = b[1]; hdr[78] = b[2]; hdr[79] = b[3];
        hash = SHA256d(hdr, 80);
        if (hash <= target) {
            found = true;
            break;
        }
        ++nonce;
        if (nonce == 0) {
            std::printf("nonce exhausted; increasing timestamp\n");
            ++ts;
            genesis = CreateGenesisBlock(params.minDifficultyBits, INITIAL_BLOCK_REWARD, ts, message, 0);
            headerSer = SerializeBlockHeader(genesis.header);
            std::memcpy(hdr, headerSer.data(), 80);
        }
    }

    if (!found) {
        std::fprintf(stderr, "genesis mining failed\n");
        return 1;
    }
    genesis.header.nonce = nonce;

    std::printf("\n=== CDX %s GENESIS ===\n", network.c_str());
    std::printf("hash:       %s\n", genesis.GetHash().getHex().c_str());
    std::printf("merkleRoot: %s\n", genesis.header.merkleRoot.getHex().c_str());
    std::printf("timestamp:  %u\n", genesis.header.timestamp);
    std::printf("nonce:      %u\n", genesis.header.nonce);
    std::printf("bits:       0x%08x\n", genesis.header.bits);
    std::printf("prevHash:   %s\n", genesis.header.prevBlockHash.getHex().c_str());
    std::printf("coinbaseTxid: %s\n", GetTxID(genesis.vtx[0]).getHex().c_str());
    std::printf("size:       %zu bytes\n", SerializeBlock(genesis).size());

    // verifikasi
    bool powOk = CheckProofOfWork(genesis.GetHash(), genesis.header.bits);
    bool merkleOk = genesis.CheckMerkleRoot();
    std::printf("\nPoW valid: %s, merkle valid: %s\n", powOk ? "YES" : "NO", merkleOk ? "YES" : "NO");

    std::printf("\nKonfigurasi untuk src/config/networks.cpp:\n");
    std::printf("  genesisHashHex = \"%s\";\n", genesis.GetHash().getHex().c_str());
    return 0;
}
