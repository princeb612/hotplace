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
    return_t ret = errorcode_t::success;

    __try2 {
        signature.clear();

        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto kty = ktyof_evp_pkey(pkey);
        switch (kty) {
            case kty_okp:     // EdDSA
            case kty_mldsa:   // MLDSA
            case kty_slhdsa:  // SLHDSA
                break;
            default:
                ret = errorcode_t::different_type;
                break;
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        /**
         * ML-DSA-44 2420
         * ML-DSA-65 3309
         * ML-DSA-87 4627
         */

        EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
        size_t dgstsize = 0;

        function_pipeline<int> pipeline;
        pipeline  //
            .run_pipe([&]() -> int { return ctx.get() ? 1 : 0; })
            .run_pipe([&]() -> int { return EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, (EVP_PKEY*)pkey); })
            .run_pipe([&]() -> int { return EVP_DigestSign(ctx.get(), nullptr, &dgstsize, stream, size); })
            .walk([&]() -> void { signature.resize(dgstsize); })
            .run_pipe([&]() -> int { return EVP_DigestSign(ctx.get(), signature.data(), &dgstsize, stream, size); })
            .walk([&]() -> void { signature.resize(dgstsize); });
        if (pipeline.failed()) {
            ret = pipeline.result_to_return_t();
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_sign::verify_digestsign(const EVP_PKEY* pkey, const binary_t& input, const binary_t& signature, uint32 flags) {
    return verify_digestsign(pkey, input.data(), input.size(), signature, flags);
}

return_t openssl_sign::verify_digestsign(const EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto kty = ktyof_evp_pkey(pkey);
        switch (kty) {
            case kty_okp:     // EdDSA
            case kty_mldsa:   // MLDSA
            case kty_slhdsa:  // SLHDSA
                break;
            default:
                ret = errorcode_t::different_type;
                break;
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());

        function_pipeline<int> pipeline;
        pipeline  //
            .set_tracer(pipeline_trace_dbg_openssl_print)
            .run_pipe([&]() -> int { return ctx.get() ? 1 : 0; })
            .run_pipe([&]() -> int { return EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, (EVP_PKEY*)pkey); })
            .run_pipe([&]() -> int { return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), stream, size); });
        if (pipeline.failed()) {
            ret = pipeline.result_to_return_t();
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
