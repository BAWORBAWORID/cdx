#pragma once
#include <cstdint>
#include <functional>
#include "blockchain/block.h"

namespace cdx {

// ---------------------------------------------------------------------------
// PoW mining — SHA256d(serialized 80-byte header) <= target.
//   Nonce habis? -> extraNonce diubah (coinbase rebuild) -> lanjut.
// TIDAK ada fake mining: hash benar-benar dihitung.
// ---------------------------------------------------------------------------

// Struktur mining dengan extra nonce
struct CBlockHeaderEx {
    CBlockHeader header;
    uint32_t extraNonce = 0; // dipakai untuk rebuild coinbase
};

// Mine header dengan target; stop bila stopFlag bernilai true.
// Mengembalikan true bila block ditemukan; header ter-update dengan nonce.
bool MineBlockHeader(CBlockHeader& header, uint32_t bits,
                     const std::function<bool()>& stopFlag = nullptr);

// cek apakah hash memenuhi target
bool CheckPoW(const uint256& hash, uint32_t bits);

} // namespace cdx
