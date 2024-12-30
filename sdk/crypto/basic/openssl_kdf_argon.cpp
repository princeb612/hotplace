/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 6070 PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2)
 *  RFC 7914 The scrypt Password-Based Key Derivation Function
 *  RFC 9106 Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
 *  - openssl-3.2 required
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/io/basic/payload.hpp>

#if defined __linux__
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace hotplace {
namespace crypto {

return_t openssl_kdf::argon2(binary_t& derived, argon2_t mode, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad,
                             const binary_t& secret, uint32 iteration_cost, uint32 parallel_cost, uint32 memory_cost) {
    return_t ret = errorcode_t::success;

    derived.clear();

#if OPENSSL_VERSION_NUMBER >= 0x30200000L

    int ret_openssl = 0;
    EVP_KDF* kdf = nullptr;
    EVP_KDF_CTX* ctx = nullptr;
    OSSL_LIB_CTX* lib_context = nullptr;
    OSSL_PARAM params[9], *p = params;
    unsigned int threads = 0;

    __try2 {
        const char* id = nullptr;
        switch (mode) {
            case argon2_t::argon2d:
                id = "argon2d";
                break;
            case argon2_t::argon2i:
                id = "argon2i";
                break;
            case argon2_t::argon2id:
                id = "argon2id";
                break;
            default:
                break;
        }
        if (nullptr == id) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        lib_context = OSSL_LIB_CTX_new();
        if (nullptr == lib_context) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        kdf = EVP_KDF_fetch(lib_context, id, nullptr);
        if (nullptr == kdf) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ctx = EVP_KDF_CTX_new(kdf);
        if (nullptr == ctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        threads = parallel_cost;
        ret_openssl = OSSL_set_max_threads(lib_context, parallel_cost);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        /* Set password */
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void*)&password[0], password.size());
        /* Set salt */
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)&salt[0], salt.size());
        /* Set optional additional data */
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_ARGON2_AD, (void*)&ad[0], ad.size());
        /* Set optional secret */
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, (void*)&secret[0], secret.size());
        /* Set iteration count */
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, (uint32_t*)&iteration_cost);
        /* Set threads performing derivation (can be decreased) */
        *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_THREADS, &threads);
        /* Set parallel cost */
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, (uint32_t*)&parallel_cost);
        /* Set memory requirement */
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, (uint32_t*)&memory_cost);
        *p = OSSL_PARAM_construct_end();

        derived.resize(dlen);
        ret_openssl = EVP_KDF_derive(ctx, &derived[0], dlen, params);
    }
    __finally2 {
        if (ctx) {
            EVP_KDF_CTX_free(ctx);
        }
        if (kdf) {
            EVP_KDF_free(kdf);
        }
        if (lib_context) {
            OSSL_LIB_CTX_free(lib_context);
        }
    }
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t openssl_kdf::argon2d(binary_t& derived, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad, const binary_t& secret,
                              uint32 iteration_cost, uint32 parallel_cost, uint32 memory_cost) {
    return argon2(derived, argon2_t::argon2d, dlen, password, salt, ad, secret, iteration_cost, parallel_cost, memory_cost);
}

return_t openssl_kdf::argon2i(binary_t& derived, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad, const binary_t& secret,
                              uint32 iteration_cost, uint32 parallel_cost, uint32 memory_cost) {
    return argon2(derived, argon2_t::argon2i, dlen, password, salt, ad, secret, iteration_cost, parallel_cost, memory_cost);
}

return_t openssl_kdf::argon2id(binary_t& derived, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad, const binary_t& secret,
                               uint32 iteration_cost, uint32 parallel_cost, uint32 memory_cost) {
    return argon2(derived, argon2_t::argon2id, dlen, password, salt, ad, secret, iteration_cost, parallel_cost, memory_cost);
}

}  // namespace crypto
}  // namespace hotplace
