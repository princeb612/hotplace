/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_sign::sign_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, binary_t& signature) {
    return sign_digest(pkey, alg, &input[0], input.size(), signature);
}

return_t openssl_sign::sign_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, binary_t& signature) {
    return sign_digest(pkey, alg, stream, size, signature);
}

return_t openssl_sign::sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, binary_t& signature) {
    return sign_rsassa_pss(pkey, alg, &input[0], input.size(), signature, -1);
}

return_t openssl_sign::sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, binary_t& signature, int saltlen) {
    return sign_rsassa_pss(pkey, alg, &input[0], input.size(), signature, saltlen);
}

return_t openssl_sign::sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, binary_t& signature) {
    return sign_rsassa_pss(pkey, alg, stream, size, signature, -1);
}

return_t openssl_sign::sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, binary_t& signature, int saltlen) {
    return_t ret = errorcode_t::success;

    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_hash hash;
    hash_context_t* hash_handle = nullptr;
    binary_t hash_value;
    int ret_openssl = 0;

    __try2 {
        signature.clear();

        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto kty = typeof_crypto_key(pkey);
        if ((kty_rsa != kty) && (kty_rsapss != kty)) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        hash.open(&hash_handle, alg);
        hash.hash(hash_handle, stream, size, hash_value);
        hash.close(hash_handle);

        EVP_MD* evp_md = (EVP_MD*)advisor->find_evp_md(alg);

        binary_t buf;
        const EVP_PKEY* key = pkey;
        RSA* rsa = (RSA*)EVP_PKEY_get0_RSA((EVP_PKEY*)key);  // openssl 3.0 EVP_PKEY_get0 family return const key pointer
        int bufsize = RSA_size(rsa);
        buf.resize(bufsize);

        ret_openssl = RSA_padding_add_PKCS1_PSS(rsa, &buf[0], &hash_value[0], evp_md, saltlen);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        signature.resize(bufsize);
        ret_openssl = RSA_private_encrypt(bufsize, &buf[0], &signature[0], rsa, RSA_NO_PADDING);
        if (ret_openssl != bufsize) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_sign::verify_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, const binary_t& signature) {
    return verify_digest(pkey, alg, &input[0], input.size(), signature);
}

return_t openssl_sign::verify_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, const binary_t& signature) {
    return verify_digest(pkey, alg, stream, size, signature);
}

return_t openssl_sign::verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, const binary_t& signature) {
    return verify_rsassa_pss(pkey, alg, &input[0], input.size(), signature, -1);
}

return_t openssl_sign::verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, const binary_t& signature, int saltlen) {
    return verify_rsassa_pss(pkey, alg, &input[0], input.size(), signature, saltlen);
}

return_t openssl_sign::verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, const binary_t& signature) {
    return verify_rsassa_pss(pkey, alg, stream, size, signature, -1);
}

return_t openssl_sign::verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, const binary_t& signature,
                                         int saltlen) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_hash hash;
    hash_context_t* hash_handle = nullptr;
    binary_t hash_value;
    int ret_openssl = 0;

    __try2 {
        if (nullptr == pkey || signature.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto kty = typeof_crypto_key(pkey);
        if ((kty_rsa != kty) && (kty_rsapss != kty)) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = errorcode_t::error_verify;

        hash.open(&hash_handle, alg);
        hash.hash(hash_handle, stream, size, hash_value);
        hash.close(hash_handle);

        EVP_MD* evp_md = (EVP_MD*)advisor->find_evp_md(alg);

        binary_t buf;
        const EVP_PKEY* key = pkey;
        RSA* rsa = (RSA*)EVP_PKEY_get0_RSA((EVP_PKEY*)key);  // openssl 3.0 EVP_PKEY_get0 family return const key pointer
        int bufsize = RSA_size(rsa);
        buf.resize(bufsize);

        RSA_public_decrypt(bufsize, &signature[0], &buf[0], rsa, RSA_NO_PADDING);
        ret_openssl = RSA_verify_PKCS1_PSS(rsa, &hash_value[0], evp_md, &buf[0], saltlen);
        if (ret_openssl < 1) {
            ret = errorcode_t::error_verify;
            __leave2;
        }

        ret = errorcode_t::success;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
