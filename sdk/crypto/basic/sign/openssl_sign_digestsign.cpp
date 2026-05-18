/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   openssl_sign_digestsign.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

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
    int ret_test = 0;

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

        EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
        ret_test = EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, (EVP_PKEY*)pkey);
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        /**
         * ML-DSA-44 2420
         * ML-DSA-65 3309
         * ML-DSA-87 4627
         */
        size_t dgstsize = 0;
        ret_test = EVP_DigestSign(ctx.get(), nullptr, &dgstsize, stream, size);
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        signature.resize(dgstsize);

        ret_test = EVP_DigestSign(ctx.get(), signature.data(), &dgstsize, stream, size);
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        signature.resize(dgstsize);
    }
    __finally2 {}
    return ret;
}

return_t openssl_sign::verify_digestsign(const EVP_PKEY* pkey, const binary_t& input, const binary_t& signature, uint32 flags) {
    return verify_digestsign(pkey, input.data(), input.size(), signature, flags);
}

return_t openssl_sign::verify_digestsign(const EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    int ret_test = 0;

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
        ret_test = EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, (EVP_PKEY*)pkey);
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_test = EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), stream, size);
        if (1 != ret_test) {
            ret = errorcode_t::error_verify;
            __leave2_trace_openssl(ret);
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
