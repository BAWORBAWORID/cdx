#pragma once
#include "rpc/server.h"
#include "blockchain/blockchain.h"
#include "mempool/mempool.h"
#include "wallet/wallet.h"
#include "mining/miner.h"
#include "p2p/server.h"

namespace cdx {

// daftarkan semua method RPC CDX
// Catatan: objek diambil sebagai POINTER agar lambda dapat menyalin nilai
// capture dengan aman (menghindari use-after-scope pada parameter referensi).
void RegisterRpcMethods(CRpcServer& server,
                        CBlockchain* blockchain,
                        CTxMemPool* mempool,
                        CWallet* wallet,
                        CMiner* miner,
                        CNetServer* net,
                        const ChainParams* params,
                        const std::function<bool(const CTransaction&)>& broadcastTx,
                        const std::function<void()>& requestMiningStop);

} // namespace cdx
