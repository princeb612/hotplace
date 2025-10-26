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
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_sign::sign_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, binary_t& signature, uint32 flags) {
    return sign_digest(pkey, alg, &input[0], input.size(), signature, flags);
}

return_t openssl_sign::sign_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, binary_t& signature, uint32 flags) {
    return sign_digest(pkey, alg, stream, size, signature, flags);
}

return_t openssl_sign::verify_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, const binary_t& signature, uint32 flags) {
    return verify_digest(pkey, alg, &input[0], input.size(), signature, flags);
}

return_t openssl_sign::verify_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, const binary_t& signature,
                                            uint32 flags) {
    return verify_digest(pkey, alg, stream, size, signature, flags);
}

}  // namespace crypto
}  // namespace hotplace
