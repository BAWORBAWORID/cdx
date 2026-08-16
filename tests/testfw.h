#pragma once
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace testfw {

struct TestCase {
    const char* name;
    void (*fn)();
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}

struct Registrar {
    Registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

inline int failures = 0;
inline int checks = 0;
inline const char* currentTest = "";

inline void reportFailure(const char* file, int line, const std::string& msg) {
    std::fprintf(stderr, "  FAIL %s:%d [%s] %s\n", file, line, currentTest, msg.c_str());
    ++failures;
}

inline int runAll(int argc, char** argv) {
    const char* filter = argc > 1 ? argv[1] : nullptr;
    int ran = 0;
    for (auto& t : registry()) {
        if (filter && std::string(t.name).find(filter) == std::string::npos) continue;
        currentTest = t.name;
        int before = failures;
        int beforeChecks = checks;
        std::printf("RUN  %s\n", t.name);
        t.fn();
        if (failures == before) {
            std::printf("PASS %s (%d checks)\n", t.name, checks - beforeChecks);
        } else {
            std::printf("FAIL %s\n", t.name);
        }
        ++ran;
    }
    std::printf("\n%d tests run, %d checks, %d failures\n", ran, checks, failures);
    return failures == 0 ? 0 : 1;
}

} // namespace testfw

#define TEST(name)                                                        \
    static void test_##name();                                            \
    static ::testfw::Registrar reg_##name(#name, &test_##name);           \
    static void test_##name()

#define CHECK(cond)                                                        \
    do {                                                                   \
        ::testfw::checks++;                                                \
        if (!(cond)) {                                                     \
            ::testfw::reportFailure(__FILE__, __LINE__, "CHECK failed: " #cond); \
        }                                                                  \
    } while (0)

#define CHECK_EQ(a, b)                                                     \
    do {                                                                   \
        ::testfw::checks++;                                                \
        auto va = (a); auto vb = (b);                                      \
        if (!(va == vb)) {                                                 \
            ::testfw::reportFailure(__FILE__, __LINE__,                    \
                std::string("CHECK_EQ failed: ") + #a + " == " + #b +     \
                " (got different values)");                                \
        }                                                                  \
    } while (0)

#define CHECK_THROW(expr)                                                  \
    do {                                                                   \
        ::testfw::checks++;                                                \
        bool threw = false;                                                \
        try { (void)(expr); } catch (...) { threw = true; }                \
        if (!threw) {                                                      \
            ::testfw::reportFailure(__FILE__, __LINE__,                    \
                "CHECK_THROW failed: " #expr " did not throw");            \
        }                                                                  \
    } while (0)
