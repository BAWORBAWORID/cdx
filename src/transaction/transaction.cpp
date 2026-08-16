#include "transaction/transaction.h"
#include "crypto/encoding.h"
#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace cdx {

// Format nilai base units -> string CDX desimal (8 digit)
std::string FormatValue(int64_t baseUnits) {
    bool neg = baseUnits < 0;
    uint64_t abs = neg ? (uint64_t)(-(baseUnits + 1)) + 1 : (uint64_t)baseUnits;
    uint64_t whole = abs / 100000000ull;
    uint64_t frac = abs % 100000000ull;
    char buf[64];
    if (frac == 0)
        std::snprintf(buf, sizeof(buf), "%llu", (unsigned long long)whole);
    else
        std::snprintf(buf, sizeof(buf), "%llu.%08llu",
                      (unsigned long long)whole, (unsigned long long)frac);
    std::string s = buf;
    // buang trailing zero pada pecahan
    if (s.find('.') != std::string::npos) {
        while (!s.empty() && s.back() == '0') s.pop_back();
        if (!s.empty() && s.back() == '.') s.pop_back();
    }
    if (neg) s = "-" + s;
    return s;
}

int64_t ParseValue(const std::string& s) {
    if (s.empty()) throw std::runtime_error("empty amount");
    bool neg = false;
    size_t i = 0;
    if (s[0] == '-') { neg = true; i = 1; }
    else if (s[0] == '+') i = 1;
    if (i >= s.size()) throw std::runtime_error("invalid amount");
    uint64_t whole = 0, frac = 0;
    int fracDigits = 0;
    bool inFrac = false;
    for (; i < s.size(); ++i) {
        char c = s[i];
        if (c == '.') {
            if (inFrac) throw std::runtime_error("invalid amount");
            inFrac = true;
            continue;
        }
        if (c < '0' || c > '9') throw std::runtime_error("invalid amount");
        if (!inFrac) {
            whole = whole * 10 + (uint64_t)(c - '0');
            if (whole > 21000000ull * 100000000ull + 1)
                throw std::runtime_error("amount too large");
        } else {
            if (fracDigits >= 8) throw std::runtime_error("too many decimals");
            frac = frac * 10 + (uint64_t)(c - '0');
            ++fracDigits;
        }
    }
    while (fracDigits < 8) { frac *= 10; ++fracDigits; }
    uint64_t total = whole * 100000000ull + frac;
    if (total > 21000000ull * 100000000ull)
        throw std::runtime_error("amount exceeds max supply");
    int64_t result = (int64_t)total;
    return neg ? -result : result;
}

} // namespace cdx
