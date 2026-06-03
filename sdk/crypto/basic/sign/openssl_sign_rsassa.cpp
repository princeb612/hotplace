/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   openssl_sign_rsassa.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_sign::sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, binary_t& signature, uint32 flags) {
    return sign_rsassa_pss(pkey, alg, input.data(), input.size(), signature, -1);
}

return_t openssl_sign::sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, binary_t& signature, int saltlen) {
    return sign_rsassa_pss(pkey, alg, input.data(), input.size(), signature, saltlen);
}

return_t openssl_sign::sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, binary_t& signature, uint32 flags) {
    return sign_rsassa_pss(pkey, alg, stream, size, signature, -1);
}

return_t openssl_sign::sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, binary_t& signature, int saltlen) {
    signature.clear();

    crypto_advisor* advisor = crypto_advisor::get_instance();
    EVP_MD* evp_md = nullptr;
    RSA* rsa = nullptr;
    binary_t buf;
    binary_t hash_value;
    int bufsize = 0;

    function_pipeline<int, osslerror_category> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != pkey) && (nullptr != stream); })
        .run_pipe([&]() -> int {
            auto kty = ktyof_evp_pkey(pkey);
            return (kty_rsa == kty || kty_rsapss == kty) ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            evp_md = (EVP_MD*)advisor->find_evp_md(alg);
            return evp_md ? 1 : 0;
        })
        .run_pipe([&]() -> return_t {
            openssl_hash hash;
            hash_context_t* hash_handle = nullptr;
            auto ret = hash.open(&hash_handle, alg);
            if (errorcode_t::success == ret) {
                ret = hash.hash(hash_handle, stream, size, hash_value);
                hash.close(hash_handle);
            }
            return ret;
        })
        .run_pipe([&]() -> int {
            rsa = (RSA*)EVP_PKEY_get0_RSA((EVP_PKEY*)pkey);
            if (nullptr == rsa) return 0;
            bufsize = RSA_size(rsa);
            buf.resize(bufsize);
            signature.resize(bufsize);
            return 1;
        })
        .run_pipe([&]() -> int { return RSA_padding_add_PKCS1_PSS(rsa, buf.data(), hash_value.data(), evp_md, saltlen); })
        .run_pipe([&]() -> int {
            auto rc = RSA_private_encrypt(bufsize, buf.data(), signature.data(), rsa, RSA_NO_PADDING);
            return (rc == bufsize) ? 1 : 0;
        });

    return pipeline.result_to_return_t();
}

return_t openssl_sign::verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, const binary_t& signature, uint32 flags) {
    return verify_rsassa_pss(pkey, alg, input.data(), input.size(), signature, -1);
}

return_t openssl_sign::verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, const binary_t& signature, int saltlen) {
    return verify_rsassa_pss(pkey, alg, input.data(), input.size(), signature, saltlen);
}

return_t openssl_sign::verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags) {
    return verify_rsassa_pss(pkey, alg, stream, size, signature, -1);
}

return_t openssl_sign::verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, const binary_t& signature, int saltlen) {
    EVP_MD* evp_md = nullptr;
    RSA* rsa = nullptr;
    binary_t buf;
    binary_t hash_value;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    int bufsize = 0;

    function_pipeline<int, osslerror_category> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != pkey) && (false == signature.empty()); })
        .run_pipe([&]() -> int {
            auto kty = ktyof_evp_pkey(pkey);
            return ((kty_rsa == kty) || (kty_rsapss == kty)) ? 1 : 0;
        })
        .run_pipe([&]() -> return_t {
            openssl_hash hash;
            hash_context_t* hash_handle = nullptr;
            auto ret = hash.open(&hash_handle, alg);
            if (errorcode_t::success == ret) {
                ret = hash.hash(hash_handle, stream, size, hash_value);
                hash.close(hash_handle);
            }
            return ret;
        })
        .run_pipe([&]() -> int {
            evp_md = (EVP_MD*)advisor->find_evp_md(alg);
            return evp_md ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            rsa = (RSA*)EVP_PKEY_get0_RSA((EVP_PKEY*)pkey);
            if (nullptr == rsa) return 0;

            bufsize = RSA_size(rsa);
            buf.resize(bufsize);
            return 1;
        })
        .run_pipe([&]() -> int { return RSA_public_decrypt(bufsize, signature.data(), buf.data(), rsa, RSA_NO_PADDING); })
        .run_pipe([&]() -> return_t {
            auto rc = RSA_verify_PKCS1_PSS(rsa, hash_value.data(), evp_md, buf.data(), saltlen);
            return (rc > 0) ? errorcode_t::success : errorcode_t::verification_failure;
        });

    return pipeline.result_to_return_t();
}

}  // namespace crypto
}  // namespace hotplace
