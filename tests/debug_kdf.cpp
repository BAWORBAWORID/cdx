#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

int main() {
    std::vector<uint8_t> salt(16, 0x42);
    int iters = 210000;
    uint8_t out[32];
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "PBKDF2", nullptr);
    std::printf("kdf fetch: %p\n", (void*)kdf);
    if (!kdf) return 1;
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    std::printf("ctx: %p\n", (void*)ctx);
    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt.data(), salt.size());
    params[2] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER, &iters);
    params[3] = OSSL_PARAM_construct_end();
    int rc = EVP_KDF_derive(ctx, out, 32, params);
    std::printf("derive rc: %d\n", rc);
    if (rc == 1) {
        std::printf("out: ");
        for (int i = 0; i < 32; ++i) std::printf("%02x", out[i]);
        std::printf("\n");
    }
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return 0;
}
