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
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_sign::sign_eddsa(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, binary_t& signature) {
    return sign_eddsa(pkey, alg, &input[0], input.size(), signature);
}

return_t openssl_sign::sign_eddsa(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, binary_t& signature) {
    return_t ret = errorcode_t::success;
    EVP_MD_CTX* ctx = nullptr;
    int ret_test = 0;

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto kty = typeof_crypto_key(pkey);
        if (kty_okp != kty) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ctx = EVP_MD_CTX_new();
        ret_test = EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, (EVP_PKEY*)pkey);
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        size_t dgstsize = 256;
        signature.resize(dgstsize);
        ret_test = EVP_DigestSign(ctx, &signature[0], &dgstsize, stream, size);
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        signature.resize(dgstsize);
    }
    __finally2 {
        if (ctx) {
            EVP_MD_CTX_destroy(ctx);
        }
    }
    return ret;
}

return_t openssl_sign::verify_eddsa(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, const binary_t& signature) {
    return verify_eddsa(pkey, alg, &input[0], input.size(), signature);
}

return_t openssl_sign::verify_eddsa(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    EVP_MD_CTX* ctx = nullptr;
    int ret_test = 0;

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto kty = typeof_crypto_key(pkey);
        if (kty_okp != kty) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = errorcode_t::error_verify;

        ctx = EVP_MD_CTX_new();
        ret_test = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, (EVP_PKEY*)pkey);
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_test = EVP_DigestVerify(ctx, &signature[0], signature.size(), stream, size);
        if (1 != ret_test) {
            ret = errorcode_t::error_verify;
            __leave2_trace_openssl(ret);
        }

        ret = errorcode_t::success;
    }
    __finally2 {
        if (ctx) {
            EVP_MD_CTX_destroy(ctx);
        }
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
