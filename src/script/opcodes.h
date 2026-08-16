#pragma once
#include <cstddef>
#include <cstdint>

namespace cdx {

// Minimal bitcoin-style script opcodes untuk P2PKH.
enum Opcode : uint8_t {
    OP_0 = 0x00,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_1 = 0x51,
    OP_2 = 0x52,
    OP_16 = 0x60,

    OP_DUP = 0x76,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_VERIFY = 0x69,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_HASH160 = 0xa9,

    OP_RETURN = 0x6a,
};

// max size script
inline constexpr size_t MAX_SCRIPT_SIZE = 10000;
inline constexpr size_t MAX_SCRIPT_ELEMENT_SIZE = 520;

} // namespace cdx
