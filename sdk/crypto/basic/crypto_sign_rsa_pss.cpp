/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_sign.hpp>

namespace hotplace {
namespace crypto {

crypto_sign_rsa_pss::crypto_sign_rsa_pss(hash_algorithm_t hashalg) : crypto_sign(hashalg) {}

return_t crypto_sign_rsa_pss::sign(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_sign s;
        ret = s.sign_rsassa_pss(pkey, get_digest(), stream, size, signature);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_sign_rsa_pss::verify(const EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_sign s;
        ret = s.verify_rsassa_pss(pkey, get_digest(), stream, size, signature);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_sign_rsa_pss::sign(const EVP_PKEY* pkey, const binary_t& input, binary_t& signature) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_sign s;
        ret = s.sign_rsassa_pss(pkey, get_digest(), input, signature);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_sign_rsa_pss::verify(const EVP_PKEY* pkey, const binary_t& input, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_sign s;
        ret = s.verify_rsassa_pss(pkey, get_digest(), input, signature);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
