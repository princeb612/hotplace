/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_sign.hpp>

namespace hotplace {
namespace crypto {

crypto_sign_ecdsa::crypto_sign_ecdsa(hash_algorithm_t hashalg) : crypto_sign(hashalg) {}

return_t crypto_sign_ecdsa::sign(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_sign s;
        ret = s.sign_ecdsa(pkey, get_digest(), stream, size, signature, flags);
    }
    __finally2 {}
    return ret;
}

return_t crypto_sign_ecdsa::verify(const EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_sign s;
        ret = s.verify_ecdsa(pkey, get_digest(), stream, size, signature, flags);
    }
    __finally2 {}
    return ret;
}

return_t crypto_sign_ecdsa::sign(const EVP_PKEY* pkey, const binary_t& input, binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_sign s;
        ret = s.sign_ecdsa(pkey, get_digest(), input, signature, flags);
    }
    __finally2 {}
    return ret;
}

return_t crypto_sign_ecdsa::verify(const EVP_PKEY* pkey, const binary_t& input, const binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_sign s;
        ret = s.verify_ecdsa(pkey, get_digest(), input, signature, flags);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
