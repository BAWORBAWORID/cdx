#include "mining/miner.h"
#include "mining/pow.h"
#include "consensus/rewards.h"
#include "consensus/difficulty.h"
#include "consensus/validation.h"
#include "blockchain/merkle.h"
#include "script/interpreter.h"
#include "wallet/address.h"
#include "transaction/serializer.h"
#include "crypto/hash.h"
#include "crypto/encoding.h"
#include "utxo/coin-selection.h"
#include <thread>
#include <chrono>
#include <cstring>
#include <ctime>

namespace cdx {

CBlock CMiner::CreateCandidateBlock(int64_t height, uint32_t bits, uint32_t timestamp,
                                    const uint256& prevHash,
                                    const CTxMemPool& mempool,
                                    const CCoinsView& view,
                                    const std::string& minerAddress,
                                    uint8_t versionByte,
                                    int64_t& feesOut) {
    CBlock blk;
    feesOut = 0;

    uint8_t minerHash[20];
    uint8_t ver;
    if (!DecodeAddress(minerAddress, ver, minerHash) || ver != versionByte) {
        // address invalid: coinbase ke OP_TRUE (mirror bitcoin genesis style)
        minerHash[0] = 0;
    }

    // --- coinbase ---
    CTransaction coinbase;
    coinbase.version = 1;
    CTxIn cbIn;
    cbIn.prevout.hash.clear();
    cbIn.prevout.n = 0xffffffff;
    // scriptSig: block height (serialized) + extraNonce placeholder + data
    // height di-encode sebagai serialized CScript number
    std::vector<uint8_t> cbScript;
    int64_t h = height;
    uint8_t hbytes[8];
    WriteU64LE(hbytes, (uint64_t)h);
    // encode CScriptNum-style (minimal push)
    if (h == 0) {
        cbScript.push_back(0x00);
    } else {
        // little-endian minimal
        uint8_t le[8];
        WriteU64LE(le, (uint64_t)h);
        int n = 8;
        while (n > 1 && le[n - 1] == 0) --n;
        if (le[n - 1] & 0x80) { le[n] = 0; ++n; }
        cbScript.push_back((uint8_t)n);
        cbScript.insert(cbScript.end(), le, le + n);
    }
    // extraNonce placeholder: 4 byte
    cbScript.push_back(0x04);
    cbScript.push_back(0x00); cbScript.push_back(0x00);
    cbScript.push_back(0x00); cbScript.push_back(0x00);
    // miner data
    const char* data = "CDX Miner";
    cbScript.push_back((uint8_t)std::strlen(data));
    cbScript.insert(cbScript.end(), data, data + std::strlen(data));
    cbIn.scriptSig = std::move(cbScript);
    cbIn.sequence = 0xffffffff;
    coinbase.vin.push_back(cbIn);

    // coinbase output: subsidy + fees
    int64_t subsidy = GetBlockSubsidy(height);
    int64_t fees = 0;

    // pilih tx dari mempool (deterministic order)
    std::vector<CTransaction> txs;
    for (const CTransaction* tx : mempool.GetTxs()) {
        // cek masih valid terhadap view
        int64_t fee = 0;
        std::string error;
        if (CheckTxInputs(*tx, view, height, fee, error)) {
            fees += fee;
            txs.push_back(*tx);
            if (txs.size() >= 500) break;
        }
    }
    feesOut = fees;

    CTxOut cbOut;
    cbOut.value = subsidy + fees;
    cbOut.scriptPubKey = BuildP2PKHScript(minerHash);
    coinbase.vout.push_back(cbOut);

    blk.vtx.push_back(std::move(coinbase));
    for (auto& tx : txs) blk.vtx.push_back(std::move(tx));

    // header
    blk.header.version = 1;
    blk.header.prevBlockHash = prevHash;
    blk.header.timestamp = timestamp;
    blk.header.bits = bits;
    blk.header.merkleRoot = ComputeMerkleRoot(blk.vtx);
    blk.header.nonce = 0;
    return blk;
}

MiningStatus CMiner::GetStatus() const {
    MiningStatus s;
    s.mining = running.load();
    s.hashCount = totalHashes.load();
    s.blocksFound = blocksFound.load();
    s.lastBlockHeight = lastHeightMined;
    s.miningAddress = miningAddress;
    s.blockReward = GetBlockSubsidy(lastHeightMined >= 0 ? lastHeightMined : 0);
    s.immatureReward = immatureReward;
    s.maturedReward = maturedReward;
    return s;
}

void CMiner::RunLoop() {
    // mining loop: akan dipanggil dalam thread
    // (implementasi membutuhkan akses blockchain; disediakan via callback
    //  yang di-set oleh node — lihat blockchain.h untuk integrasi)
    running = true;
    while (!stopRequested) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    running = false;
}

void CMiner::Start() {
    if (running.load()) return;
    stopRequested = false;
    std::thread t([this]() { RunLoop(); });
    t.detach();
}

} // namespace cdx
