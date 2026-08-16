#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include "blockchain/block.h"
#include "p2p/protocol.h"

namespace cdx {

// ---------------------------------------------------------------------------
// Chain sync:
//   Discover peer -> handshake -> getheaders -> validate headers
//   -> download blocks -> validate -> apply UTXO -> synced
// Restart harus dapat resume synchronization.
// ---------------------------------------------------------------------------

// bangun payload getheaders (dari locator hashes)
std::vector<uint8_t> BuildGetHeadersPayload(const std::vector<uint256>& locator,
                                            const uint256& hashStop);

// parse payload getheaders/getblocks: locator + hashStop
bool ParseGetHeadersPayload(const std::vector<uint8_t>& payload,
                            std::vector<uint256>& locator, uint256& hashStop);

// parse payload headers -> daftar header
bool ParseHeadersPayload(const std::vector<uint8_t>& payload, std::vector<CBlockHeader>& headers);

// bangun payload headers (dari daftar header)
std::vector<uint8_t> BuildHeadersPayload(const std::vector<CBlockHeader>& headers);

// bangun payload getblocks
std::vector<uint8_t> BuildGetBlocksPayload(const std::vector<uint256>& locator,
                                           const uint256& hashStop);

// parse payload block (serialized CBlock)
bool ParseBlockPayload(const std::vector<uint8_t>& payload, CBlock& blk);

// parse payload tx
bool ParseTxPayload(const std::vector<uint8_t>& payload, CTransaction& tx);

// locator: hashes dari tip ke belakang (1,1,2,4,8...)
std::vector<uint256> BuildLocator(const std::vector<uint256>& chainHashes, int64_t tipHeight);

} // namespace cdx
