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
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_sign::sign_digest(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, binary_t& signature, uint32 flags) {
    return sign_digest(pkey, alg, &input[0], input.size(), signature, flags);
}

return_t openssl_sign::sign_digest(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    EVP_MD_CTX* md_context = nullptr;
    int ret_openssl = 1;
    size_t dgstsize = 0;

    __try2 {
        signature.resize(0);
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        EVP_MD* evp_md = (EVP_MD*)advisor->find_evp_md(alg);

        md_context = EVP_MD_CTX_create();
        if (nullptr == md_context) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_DigestInit_ex(md_context, evp_md, nullptr);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        ret_openssl = EVP_DigestSignInit(md_context, nullptr, evp_md, nullptr, (EVP_PKEY*)pkey);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        ret_openssl = EVP_DigestSignUpdate(md_context, stream, size);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        ret_openssl = EVP_DigestSignFinal(md_context, nullptr, &dgstsize);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        signature.resize(dgstsize);
        EVP_DigestSignFinal(md_context, &signature[0], &dgstsize);
    }
    __finally2 {
        if (nullptr != md_context) {
            EVP_MD_CTX_destroy(md_context);
        }
    }
    return ret;
}

return_t openssl_sign::verify_digest(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, const binary_t& signature, uint32 flags) {
    return verify_digest(pkey, alg, &input[0], input.size(), signature, flags);
}

return_t openssl_sign::verify_digest(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    EVP_MD_CTX* md_context = nullptr;
    int ret_openssl = 1;

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = errorcode_t::error_verify;

        EVP_MD* evp_md = (EVP_MD*)advisor->find_evp_md(alg);

        md_context = EVP_MD_CTX_create();
        if (nullptr == md_context) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_DigestInit_ex(md_context, evp_md, nullptr);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_DigestVerifyInit(md_context, nullptr, evp_md, nullptr, (EVP_PKEY*)pkey);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_DigestVerifyUpdate(md_context, stream, size);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_DigestVerifyFinal(md_context, &signature[0], signature.size());
        if (ret_openssl < 1) {
            ret = errorcode_t::error_verify;
            __leave2_trace_openssl(ret);
        }

        ret = errorcode_t::success;
    }
    __finally2 {
        if (nullptr != md_context) {
            EVP_MD_CTX_destroy(md_context);
        }
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
