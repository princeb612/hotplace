/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>

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

}
}  // namespace
