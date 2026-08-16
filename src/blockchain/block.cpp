#include "blockchain/block.h"
#include "blockchain/merkle.h"
#include "transaction/serializer.h"
#include "crypto/hash.h"

namespace cdx {

uint256 CBlockHeader::GetHash() const {
    auto ser = SerializeBlockHeader(*this);
    return SHA256d(ser.data(), ser.size());
}

bool CBlock::CheckMerkleRoot() const {
    return ComputeMerkleRoot(vtx) == header.merkleRoot;
}

} // namespace cdx
