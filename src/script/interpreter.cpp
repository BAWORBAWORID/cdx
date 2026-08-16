#include "script/interpreter.h"
#include "script/opcodes.h"
#include "crypto/hash.h"
#include "crypto/keys.h"
#include <cstring>

namespace cdx {

std::vector<uint8_t> BuildP2PKHScript(const uint8_t hash160[20]) {
    std::vector<uint8_t> s;
    s.push_back(OP_DUP);
    s.push_back(OP_HASH160);
    s.push_back(0x14); // push 20 bytes
    s.insert(s.end(), hash160, hash160 + 20);
    s.push_back(OP_EQUALVERIFY);
    s.push_back(OP_CHECKSIG);
    return s;
}

bool IsP2PKHScript(const std::vector<uint8_t>& script) {
    // OP_DUP OP_HASH160 0x14 <20> OP_EQUALVERIFY OP_CHECKSIG = 25 byte
    if (script.size() != 25) return false;
    return script[0] == OP_DUP &&
           script[1] == OP_HASH160 &&
           script[2] == 0x14 &&
           script[23] == OP_EQUALVERIFY &&
           script[24] == OP_CHECKSIG;
}

bool ExtractP2PKHHash(const std::vector<uint8_t>& script, uint8_t hash160[20]) {
    if (!IsP2PKHScript(script)) return false;
    std::memcpy(hash160, script.data() + 3, 20);
    return true;
}

namespace {
// interpretasi push opcode; mengembalikan false bila opcode bukan data push murni
bool ParsePush(const uint8_t* p, size_t len, size_t& consumed, std::vector<uint8_t>& data) {
    if (len < 1) return false;
    uint8_t op = p[0];
    if (op >= 1 && op <= 75) {
        size_t n = op;
        if (len < 1 + n) return false;
        data.assign(p + 1, p + 1 + n);
        consumed = 1 + n;
        return true;
    }
    if (op == OP_PUSHDATA1) {
        if (len < 2) return false;
        size_t n = p[1];
        if (len < 2 + n) return false;
        data.assign(p + 2, p + 2 + n);
        consumed = 2 + n;
        return true;
    }
    if (op == OP_PUSHDATA2) {
        if (len < 3) return false;
        size_t n = (size_t)p[1] | ((size_t)p[2] << 8);
        if (len < 3 + n) return false;
        data.assign(p + 3, p + 3 + n);
        consumed = 3 + n;
        return true;
    }
    if (op == OP_PUSHDATA4) {
        if (len < 5) return false;
        size_t n = 0;
        for (int i = 0; i < 4; ++i) n |= (size_t)p[1 + i] << (8 * i);
        if (len < 5 + n) return false;
        data.assign(p + 5, p + 5 + n);
        consumed = 5 + n;
        return true;
    }
    return false; // bukan data push murni
}
} // namespace

void GetScriptSigPubKey(const std::vector<uint8_t>& scriptSig, std::vector<uint8_t>& pubkey) {
    pubkey.clear();
    size_t pos = 0;
    std::vector<uint8_t> last;
    while (pos < scriptSig.size()) {
        size_t consumed = 0;
        std::vector<uint8_t> data;
        if (!ParsePush(scriptSig.data() + pos, scriptSig.size() - pos, consumed, data)) break;
        last = data;
        pos += consumed;
    }
    pubkey = last;
}

bool EvalScript(const std::vector<uint8_t>& script,
                const uint8_t* hash32,
                std::vector<std::vector<uint8_t>>& stack,
                std::string& error) {
    if (script.size() > MAX_SCRIPT_SIZE) {
        error = "script too large";
        return false;
    }
    size_t pos = 0;
    int opCount = 0;
    while (pos < script.size()) {
        ++opCount;
        if (opCount > 201) {
            error = "too many operations";
            return false;
        }
        uint8_t op = script[pos];
        // data push
        size_t consumed = 0;
        std::vector<uint8_t> pushed;
        if (ParsePush(script.data() + pos, script.size() - pos, consumed, pushed)) {
            if (pushed.size() > MAX_SCRIPT_ELEMENT_SIZE) {
                error = "push too large";
                return false;
            }
            stack.push_back(std::move(pushed));
            pos += consumed;
            continue;
        }
        ++pos;
        switch (op) {
            case OP_DUP: {
                if (stack.empty()) { error = "OP_DUP: empty stack"; return false; }
                stack.push_back(stack.back());
                break;
            }
            case OP_EQUAL:
            case OP_EQUALVERIFY: {
                if (stack.size() < 2) { error = "OP_EQUAL: stack underflow"; return false; }
                auto a = std::move(stack.back()); stack.pop_back();
                auto b = std::move(stack.back()); stack.pop_back();
                bool eq = (a == b);
                if (op == OP_EQUALVERIFY) {
                    if (!eq) { error = "OP_EQUALVERIFY failed"; return false; }
                } else {
                    stack.push_back(eq ? std::vector<uint8_t>{1} : std::vector<uint8_t>{});
                }
                break;
            }
            case OP_VERIFY: {
                if (stack.empty()) { error = "OP_VERIFY: empty stack"; return false; }
                auto v = stack.back();
                if (v.empty() || (v.size() == 1 && v[0] == 0)) {
                    error = "OP_VERIFY failed";
                    return false;
                }
                stack.pop_back();
                break;
            }
            case OP_HASH160: {
                if (stack.empty()) { error = "OP_HASH160: empty stack"; return false; }
                auto v = stack.back(); stack.pop_back();
                uint8_t h[20];
                HASH160(v.data(), v.size(), h);
                stack.push_back(std::vector<uint8_t>(h, h + 20));
                break;
            }
            case OP_CHECKSIG:
            case OP_CHECKSIGVERIFY: {
                if (stack.size() < 2) { error = "OP_CHECKSIG: stack underflow"; return false; }
                auto pubkey = std::move(stack.back()); stack.pop_back();
                auto sig = std::move(stack.back()); stack.pop_back();
                if (!hash32) { error = "no hash for CHECKSIG"; return false; }
                bool ok = VerifySignature(hash32, 32, sig.data(), sig.size(), pubkey.data(), pubkey.size());
                if (op == OP_CHECKSIGVERIFY) {
                    if (!ok) { error = "OP_CHECKSIGVERIFY failed"; return false; }
                } else {
                    stack.push_back(ok ? std::vector<uint8_t>{1} : std::vector<uint8_t>{});
                }
                break;
            }
            case OP_RETURN: {
                error = "OP_RETURN";
                return false;
            }
            default:
                // OP_0 / OP_1 .. OP_16
                if (op == OP_0) {
                    stack.push_back({});
                } else if (op >= OP_1 && op <= OP_16) {
                    stack.push_back(std::vector<uint8_t>{uint8_t(op - OP_1 + 1)});
                } else if (op == OP_1NEGATE) {
                    stack.push_back(std::vector<uint8_t>{0x81});
                } else {
                    error = "unsupported opcode";
                    return false;
                }
        }
    }
    return true;
}

bool VerifyScript(const std::vector<uint8_t>& scriptSig,
                  const std::vector<uint8_t>& scriptPubKey,
                  const uint8_t* hash32,
                  std::string& error) {
    // jalankan scriptSig dulu, lalu scriptPubKey dengan stack yang sama
    std::vector<std::vector<uint8_t>> stack;
    if (!EvalScript(scriptSig, hash32, stack, error)) return false;
    if (!EvalScript(scriptPubKey, hash32, stack, error)) return false;
    if (stack.empty()) {
        error = "empty stack after script";
        return false;
    }
    auto top = stack.back();
    if (top.empty() || (top.size() == 1 && top[0] == 0)) {
        error = "false stack top";
        return false;
    }
    return true;
}

} // namespace cdx
