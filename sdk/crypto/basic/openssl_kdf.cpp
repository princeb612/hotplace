/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
#include <openssl/thread.h>
#endif

namespace hotplace {
namespace crypto {

return_t kdf_hkdf (binary_t& derived, size_t dlen, binary_t const& key, binary_t const& salt, binary_t const& info, hash_algorithm_t alg)
{
    return_t ret = errorcode_t::success;
    EVP_PKEY_CTX *ctx = nullptr;
    int ret_openssl = 0;
    const EVP_MD* md = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        md = advisor->find_evp_md (alg);
        if (nullptr == md) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        ctx = EVP_PKEY_CTX_new_id (EVP_PKEY_HKDF, NULL);
        if (nullptr == ctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY_derive_init (ctx);
        EVP_PKEY_CTX_set_hkdf_md (ctx, md);
        EVP_PKEY_CTX_set1_hkdf_key (ctx, &key[0], key.size ());
        EVP_PKEY_CTX_set1_hkdf_salt (ctx, &salt[0], salt.size ());
        EVP_PKEY_CTX_add1_hkdf_info (ctx, &info[0], info.size ());

        derived.resize (dlen);
        ret_openssl = EVP_PKEY_derive (ctx, &derived[0], &dlen);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t kdf_pbkdf2 (binary_t& derived, size_t dlen, std::string const& password, binary_t const& salt, int iter, hash_algorithm_t alg)
{
    return_t ret = errorcode_t::success;
    const EVP_MD* md = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        md = advisor->find_evp_md (alg);
        if (nullptr == md) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        derived.resize (dlen);
        PKCS5_PBKDF2_HMAC (password.c_str (), password.size (), &salt[0], salt.size (), iter, md, dlen, &derived[0]);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t kdf_scrypt (binary_t& derived, size_t dlen, std::string const& password, binary_t const& salt, int n, int r, int p)
{
    return_t ret = errorcode_t::success;
    EVP_PKEY_CTX *ctx = nullptr;
    int ret_openssl = 0;

    __try2
    {
        ctx = EVP_PKEY_CTX_new_id (EVP_PKEY_SCRYPT, NULL);
        if (nullptr == ctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY_derive_init (ctx);
        EVP_PKEY_CTX_set1_pbe_pass (ctx, password.c_str (), password.size ());
        EVP_PKEY_CTX_set1_scrypt_salt (ctx, &salt[0], salt.size ());
        EVP_PKEY_CTX_set_scrypt_N (ctx, n);
        EVP_PKEY_CTX_set_scrypt_r (ctx, r);
        EVP_PKEY_CTX_set_scrypt_p (ctx, p);

        derived.resize (dlen);
        ret_openssl = EVP_PKEY_derive (ctx, &derived[0], &dlen);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
    }
    __finally2
    {
        if (ctx) {
            EVP_PKEY_CTX_free (ctx);
        }
    }
    return ret;
}

#if OPENSSL_VERSION_NUMBER >= 0x30200000L

return_t kdf_argon2 (binary_t& derived, argon2_t mode, size_t dlen, binary_t const& password, binary_t const& salt,
                     binary_t const& ad, binary_t const& secret, uint32 iteration_cost, uint32 parallel_cost, uint32 memory_cost)
{
    return_t ret = errorcode_t::success;
    int ret_openssl = 0;
    EVP_KDF* kdf = nullptr;
    EVP_KDF_CTX* ctx = nullptr;
    OSSL_LIB_CTX* lib_context = nullptr;
    OSSL_PARAM params[9], *p = params;
    uint32 threads = 0;

    __try2
    {
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

        lib_context = OSSL_LIB_CTX_new ();
        if (nullptr == lib_context) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        kdf = EVP_KDF_fetch (lib_context, id, nullptr);
        if (nullptr == kdf) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ctx = EVP_KDF_CTX_new (kdf);
        if (nullptr == ctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        threads = parallel_cost;
        ret_openssl = OSSL_set_max_threads (lib_context, parallel_cost);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        uint64 max_threads = OSSL_get_max_threads (lib_context);
        if (0 == max_threads) {
            threads = 1;
        } else if (max_threads < parallel_cost) {
            threads = max_threads;
        }

        /* Set password */
        *p++ = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_PASSWORD, (void*) &password[0], password.size ());
        /* Set salt */
        *p++ = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_SALT, (void*) &salt[0], salt.size ());
        /* Set optional additional data */
        *p++ = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_ARGON2_AD, (void*) &ad[0], ad.size ());
        /* Set optional secret */
        *p++ = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_SECRET, (void*) &secret[0], secret.size ());
        /* Set iteration count */
        *p++ = OSSL_PARAM_construct_uint32 (OSSL_KDF_PARAM_ITER, &iteration_cost);
        /* Set threads performing derivation (can be decreased) */
        *p++ = OSSL_PARAM_construct_uint (OSSL_KDF_PARAM_THREADS, &threads);
        /* Set parallel cost */
        *p++ = OSSL_PARAM_construct_uint32 (OSSL_KDF_PARAM_ARGON2_LANES, &parallel_cost);
        /* Set memory requirement */
        *p++ = OSSL_PARAM_construct_uint32 (OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory_cost);
        *p = OSSL_PARAM_construct_end ();

        derived.resize (dlen);
        ret_openssl = EVP_KDF_derive (ctx, &derived[0], dlen, params);
    }
    __finally2
    {
        if (ctx) {
            EVP_KDF_CTX_free (ctx);
        }
        if (kdf) {
            EVP_KDF_free (kdf);
        }
        if (lib_context) {
            OSSL_LIB_CTX_free (lib_context);
        }
    }
    return ret;
}

return_t kdf_argon2d (binary_t& derived, size_t dlen, binary_t const& password, binary_t const& salt,
                      binary_t const& ad, binary_t const& secret, uint32 iteration_cost, uint32 parallel_cost, uint32 memory_cost)
{
    return kdf_argon2 (derived, argon2_t::argon2d, dlen, password, salt, ad, secret, iteration_cost, parallel_cost, memory_cost);
}

return_t kdf_argon2i (binary_t& derived, size_t dlen, binary_t const& password, binary_t const& salt,
                      binary_t const& ad, binary_t const& secret, uint32 iteration_cost, uint32 parallel_cost, uint32 memory_cost)
{
    return kdf_argon2 (derived, argon2_t::argon2i, dlen, password, salt, ad, secret, iteration_cost, parallel_cost, memory_cost);
}

return_t kdf_argon2id (binary_t& derived, size_t dlen, binary_t const& password, binary_t const& salt,
                       binary_t const& ad, binary_t const& secret, uint32 iteration_cost, uint32 parallel_cost, uint32 memory_cost)
{
    return kdf_argon2 (derived, argon2_t::argon2id, dlen, password, salt, ad, secret, iteration_cost, parallel_cost, memory_cost);
}

#endif

}
}  // namespace
