/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/evp_key.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_sign::sign_hmac(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, binary_t& signature, uint32 flags) {
    return sign_digest(pkey, alg, &input[0], input.size(), signature, flags);
}

return_t openssl_sign::sign_hmac(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, binary_t& signature, uint32 flags) {
    return sign_digest(pkey, alg, stream, size, signature, flags);
}

return_t openssl_sign::verify_hmac(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, const binary_t& signature, uint32 flags) {
    return verify_hmac(pkey, alg, &input[0], input.size(), signature, flags);
}

return_t openssl_sign::verify_hmac(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        binary_t result;
        ret = sign_digest(pkey, alg, stream, size, result, flags);
        if (result != signature) {
            ret = errorcode_t::error_verify;
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
