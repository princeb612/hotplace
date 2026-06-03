/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   openssl_sign_digestsign.cpp
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

return_t openssl_sign::sign_digestsign(const EVP_PKEY* pkey, const binary_t& input, binary_t& signature, uint32 flags) {
    return sign_digestsign(pkey, input.data(), input.size(), signature, flags);
}

return_t openssl_sign::sign_digestsign(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature, uint32 flags) {
    signature.clear();

    /**
     * ML-DSA-44 2420
     * ML-DSA-65 3309
     * ML-DSA-87 4627
     */

    EVP_MD_CTX_ptr ctx;
    size_t dgstsize = 0;

    function_pipeline<int, osslerror_category> pipeline;
    pipeline  //
        .test_parameter([&]() -> bool { return (nullptr != pkey) && (nullptr != stream); })
        .run_pipe([&]() -> return_t {
            auto kty = ktyof_evp_pkey(pkey);
            switch (kty) {
                case kty_okp:     // EdDSA
                case kty_mldsa:   // MLDSA
                case kty_slhdsa:  // SLHDSA
                    return errorcode_t::success;
                default:
                    return errorcode_t::different_type;
            }
        })
        .run_pipe([&]() -> int {
            ctx = std::move(EVP_MD_CTX_ptr(EVP_MD_CTX_new()));
            return ctx.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, (EVP_PKEY*)pkey); })
        .run_pipe([&]() -> int { return EVP_DigestSign(ctx.get(), nullptr, &dgstsize, stream, size); })
        .run_pipe([&]() -> int {
            signature.resize(dgstsize);
            auto rc = EVP_DigestSign(ctx.get(), signature.data(), &dgstsize, stream, size);
            signature.resize(dgstsize);
            return rc;
        });

    return pipeline.result_to_return_t();
}

return_t openssl_sign::verify_digestsign(const EVP_PKEY* pkey, const binary_t& input, const binary_t& signature, uint32 flags) {
    return verify_digestsign(pkey, input.data(), input.size(), signature, flags);
}

return_t openssl_sign::verify_digestsign(const EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags) {
    EVP_MD_CTX_ptr ctx;

    function_pipeline<int, osslerror_category> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != pkey) && (nullptr != stream); })
        .run_pipe([&]() -> return_t {
            auto kty = ktyof_evp_pkey(pkey);
            switch (kty) {
                case kty_okp:     // EdDSA
                case kty_mldsa:   // MLDSA
                case kty_slhdsa:  // SLHDSA
                    return errorcode_t::success;
                default:
                    return errorcode_t::different_type;
            }
        })
        .run_pipe([&]() -> int {
            ctx = std::move(EVP_MD_CTX_ptr(EVP_MD_CTX_new()));
            return ctx.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, (EVP_PKEY*)pkey); })
        .run_pipe([&]() -> int { return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), stream, size); });

    return pipeline.result_to_return_t();
}

}  // namespace crypto
}  // namespace hotplace
