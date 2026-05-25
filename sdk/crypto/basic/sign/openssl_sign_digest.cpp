/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   openssl_sign_digest.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_sign::sign_digest(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, binary_t& signature, uint32 flags) {
    return sign_digest(pkey, alg, input.data(), input.size(), signature, flags);
}

return_t openssl_sign::sign_digest(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, binary_t& signature, uint32 flags) {
    signature.resize(0);

    crypto_advisor* advisor = crypto_advisor::get_instance();
    EVP_MD* evp_md = (EVP_MD*)advisor->find_evp_md(alg);
    size_t dgstsize = 0;

    EVP_MD_CTX_ptr md_context;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != pkey && nullptr != stream); })
        .run_pipe([&]() -> int {
            md_context = std::move(EVP_MD_CTX_ptr(EVP_MD_CTX_new()));
            return md_context.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_DigestInit_ex(md_context.get(), evp_md, nullptr); })
        .run_pipe([&]() -> int { return EVP_DigestSignInit(md_context.get(), nullptr, evp_md, nullptr, (EVP_PKEY*)pkey); })
        .run_pipe([&]() -> int { return EVP_DigestSignUpdate(md_context.get(), stream, size); })
        .run_pipe([&]() -> int { return EVP_DigestSignFinal(md_context.get(), nullptr, &dgstsize); })
        .walk([&]() -> void { signature.resize(dgstsize); })
        .run_pipe([&]() -> int { return EVP_DigestSignFinal(md_context.get(), signature.data(), &dgstsize); });
    return pipeline.result_to_return_t();
}

return_t openssl_sign::verify_digest(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, const binary_t& signature, uint32 flags) {
    return verify_digest(pkey, alg, input.data(), input.size(), signature, flags);
}

return_t openssl_sign::verify_digest(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    EVP_MD* evp_md = (EVP_MD*)advisor->find_evp_md(alg);

    EVP_MD_CTX_ptr md_context;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != pkey && nullptr != stream); })
        .run_pipe([&]() -> int {
            md_context = std::move(EVP_MD_CTX_ptr(EVP_MD_CTX_new()));
            return md_context.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_DigestInit_ex(md_context.get(), evp_md, nullptr); })
        .run_pipe([&]() -> int { return EVP_DigestVerifyInit(md_context.get(), nullptr, evp_md, nullptr, (EVP_PKEY*)pkey); })
        .run_pipe([&]() -> int { return EVP_DigestVerifyUpdate(md_context.get(), stream, size); })
        .run_pipe([&]() -> int { return EVP_DigestVerifyFinal(md_context.get(), signature.data(), signature.size()); });
    return pipeline.result_to_return_t();
}

}  // namespace crypto
}  // namespace hotplace
