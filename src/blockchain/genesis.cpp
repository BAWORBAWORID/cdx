#include "blockchain/genesis.h"
#include "blockchain/merkle.h"
#include "transaction/serializer.h"
#include "crypto/hash.h"
#include "crypto/encoding.h"
#include "crypto/uint256.h"
#include <cstring>
#include <stdexcept>

namespace cdx {

CBlock CreateGenesisBlock(uint32_t bits, int64_t rewardBase, uint32_t timestamp,
                          const std::string& message, uint32_t nonce) {
    CBlock blk;
    // coinbase genesis: reward ke OP_TRUE script (mirror bitcoin genesis style)
    CTransaction coinbase;
    coinbase.version = 1;
    CTxIn cbIn;
    cbIn.prevout.hash.clear();
    cbIn.prevout.n = 0xffffffff;
    cbIn.sequence = 0xffffffff;
    cbIn.scriptSig.assign(message.begin(), message.end());
    // scriptSig harus minimal 2 byte (rule coinbase) — prepend height placeholder
    // gunakan: push message sebagai data
    std::vector<uint8_t> sig;
    sig.push_back((uint8_t)message.size());
    sig.insert(sig.end(), message.begin(), message.end());
    cbIn.scriptSig = std::move(sig);
    coinbase.vin.push_back(cbIn);

    CTxOut cbOut;
    cbOut.value = rewardBase;
    // scriptPubKey: OP_TRUE (0x51) — seperti bitcoin genesis
    cbOut.scriptPubKey = std::vector<uint8_t>{0x51};
    coinbase.vout.push_back(cbOut);

    blk.vtx.push_back(std::move(coinbase));
    blk.header.version = 1;
    blk.header.prevBlockHash.clear();
    blk.header.merkleRoot = ComputeMerkleRoot(blk.vtx);
    blk.header.timestamp = timestamp;
    blk.header.bits = bits;
    blk.header.nonce = nonce;
    return blk;
}

CBlock GetGenesisBlock(const ChainParams& params) {
    return CreateGenesisBlock(params.minDifficultyBits, INITIAL_BLOCK_REWARD,
                              CDX_GENESIS_TIMESTAMP, GetGenesisMessage(), params.genesisNonce);
}

uint256 GetGenesisHash(const ChainParams& params) {
    if (params.genesisHashHex.empty())
        throw std::runtime_error("genesis hash not configured for network " + params.name);
    return uint256::fromHexReversed(params.genesisHashHex);
}

} // namespace cdx
