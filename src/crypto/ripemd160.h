#pragma once
#include <cstddef>
#include <cstdint>

namespace cdx {

// Implementasi RIPEMD-160 (standard algorithm, public domain style)
// Output 20 byte big-endian.
void ripemd160(const uint8_t* data, size_t len, uint8_t out[20]);

} // namespace cdx
