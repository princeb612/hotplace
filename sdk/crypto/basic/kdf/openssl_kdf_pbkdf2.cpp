/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 6070 PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2)
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

return_t openssl_kdf::pbkdf2(binary_t& derived, hash_algorithm_t alg, size_t dlen, const std::string& password, const binary_t& salt, int iter) {
    return pbkdf2(derived, alg, dlen, password.c_str(), password.size(), &salt[0], salt.size(), iter);
}

return_t openssl_kdf::pbkdf2(binary_t& derived, const char* alg, size_t dlen, const std::string& password, const binary_t& salt, int iter) {
    return pbkdf2(derived, alg, dlen, password.c_str(), password.size(), &salt[0], salt.size(), iter);
}

return_t openssl_kdf::pbkdf2(binary_t& derived, hash_algorithm_t alg, size_t dlen, const binary_t& password, const binary_t& salt, int iter) {
    return pbkdf2(derived, alg, dlen, (char*)&password[0], password.size(), &salt[0], salt.size(), iter);
}

return_t openssl_kdf::pbkdf2(binary_t& derived, const char* alg, size_t dlen, const binary_t& password, const binary_t& salt, int iter) {
    return pbkdf2(derived, alg, dlen, (char*)&password[0], password.size(), &salt[0], salt.size(), iter);
}

return_t openssl_kdf::pbkdf2(binary_t& derived, hash_algorithm_t alg, size_t dlen, const char* password, size_t size_password, const byte_t* salt,
                             size_t size_salt, int iter) {
    return_t ret = errorcode_t::success;
    const EVP_MD* md = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        derived.clear();

        if (nullptr == password || nullptr == salt) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        md = advisor->find_evp_md(alg);
        if (nullptr == md) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        derived.resize(dlen);
        PKCS5_PBKDF2_HMAC(password, size_password, salt, size_salt, iter, md, dlen, &derived[0]);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_kdf::pbkdf2(binary_t& derived, const char* alg, size_t dlen, const char* password, size_t size_password, const byte_t* salt, size_t size_salt,
                             int iter) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        derived.clear();

        if (nullptr == alg) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_digest_t* hint = advisor->hintof_digest(alg);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        ret = pbkdf2(derived, typeof_alg(hint), dlen, password, size_password, salt, size_salt, iter);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
