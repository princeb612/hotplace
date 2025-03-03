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
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>

#if defined __linux__
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace hotplace {
namespace crypto {

return_t openssl_kdf::scrypt(binary_t& derived, size_t dlen, const std::string& password, const binary_t& salt, int n, int r, int p) {
    return_t ret = errorcode_t::success;
    EVP_PKEY_CTX* ctx = nullptr;
    int ret_openssl = 0;
    __try2 {
        derived.clear();

#if OPENSSL_VERSION_NUMBER < 0x30000000L
        if (0 == salt.size()) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
#endif
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, nullptr);
        if (nullptr == ctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_CTX_set1_pbe_pass(ctx, password.c_str(), password.size());
        EVP_PKEY_CTX_set1_scrypt_salt(ctx, &salt[0], salt.size());
        EVP_PKEY_CTX_set_scrypt_N(ctx, n);
        EVP_PKEY_CTX_set_scrypt_r(ctx, r);
        EVP_PKEY_CTX_set_scrypt_p(ctx, p);

        derived.resize(dlen);
        ret_openssl = EVP_PKEY_derive(ctx, &derived[0], &dlen);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
    }
    __finally2 {
        if (ctx) {
            EVP_PKEY_CTX_free(ctx);
        }
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
