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
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>

namespace hotplace {
namespace crypto {

crypto_sign_mldsa::crypto_sign_mldsa() : crypto_sign(hash_alg_unknown) {}

return_t crypto_sign_mldsa::sign(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_sign s;
        ret = s.sign_mldsa(pkey, stream, size, signature, flags);
    }
    __finally2 {}
    return ret;
}

return_t crypto_sign_mldsa::verify(const EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_sign s;
        ret = s.verify_mldsa(pkey, stream, size, signature, flags);
    }
    __finally2 {}
    return ret;
}

return_t crypto_sign_mldsa::sign(const EVP_PKEY* pkey, const binary_t& input, binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_sign s;
        ret = s.sign_mldsa(pkey, input, signature, flags);
    }
    __finally2 {}
    return ret;
}

return_t crypto_sign_mldsa::verify(const EVP_PKEY* pkey, const binary_t& input, const binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_sign s;
        ret = s.verify_mldsa(pkey, input, signature, flags);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
