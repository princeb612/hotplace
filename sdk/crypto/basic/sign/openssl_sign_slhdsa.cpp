/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   openssl_sign_slhdsa.cpp
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

return_t openssl_sign::sign_slhdsa(const EVP_PKEY* pkey, const binary_t& input, binary_t& signature, uint32 flags) {
    return sign_digestsign(pkey, input, signature, flags);
}

return_t openssl_sign::sign_slhdsa(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature, uint32 flags) {
    return sign_digestsign(pkey, stream, size, signature, flags);
}

return_t openssl_sign::verify_slhdsa(const EVP_PKEY* pkey, const binary_t& input, const binary_t& signature, uint32 flags) {
    return verify_digestsign(pkey, input, signature, flags);
}

return_t openssl_sign::verify_slhdsa(const EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags) {
    return verify_digestsign(pkey, stream, size, signature, flags);
}

}  // namespace crypto
}  // namespace hotplace
