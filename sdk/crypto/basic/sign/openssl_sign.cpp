/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   openssl_sign.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>

namespace hotplace {
namespace crypto {

openssl_sign::openssl_sign() {}

openssl_sign::~openssl_sign() {}

return_t openssl_sign::sign(const EVP_PKEY* pkey, signature_t sig, const binary_t& input, binary_t& signature, uint32 flags) {
    return sign(pkey, sig, input.data(), input.size(), signature, flags);
}

return_t openssl_sign::sign(const EVP_PKEY* pkey, signature_t sig, const byte_t* stream, size_t size, binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto kty = ktyof_evp_pkey(pkey);

        const hint_signature_t* hint = advisor->hintof_signature(sig);
        if (nullptr == hint) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
        auto category = categoryof(hint);
        hash_algorithm_t hash_alg = typeof_alg(hint);

        switch (kty) {
            case kty_oct:
                switch (category) {
                    case sig_category_t::dgst:
                        ret = sign_digest(pkey, hash_alg, stream, size, signature);
                        break;
                    case sig_category_t::hmac:
                        ret = sign_hmac(pkey, hash_alg, stream, size, signature);
                        break;
                    default:
                        ret = errorcode_t::bad_request;
                        break;
                }
                break;
            case kty_rsa:
            case kty_rsapss:
                switch (category) {
                    case sig_category_t::rsassa_pkcs15:
                        ret = sign_rsassa_pkcs15(pkey, hash_alg, stream, size, signature);
                        break;
                    case sig_category_t::rsassa_pss:
                        ret = sign_rsassa_pss(pkey, hash_alg, stream, size, signature);
                        break;
                    default:
                        ret = errorcode_t::bad_request;
                        break;
                }
                break;
            case kty_ec:
                ret = sign_ecdsa(pkey, hash_alg, stream, size, signature, flags);
                break;
            case kty_okp:
                ret = sign_digestsign(pkey, stream, size, signature);
                break;
            case kty_dsa:
                ret = sign_dsa(pkey, hash_alg, stream, size, signature);
                break;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
            case kty_mldsa:
            case kty_slhdsa:
                ret = sign_digestsign(pkey, stream, size, signature);
                break;
#endif
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_sign::verify(const EVP_PKEY* pkey, signature_t sig, const binary_t& input, const binary_t& signature, uint32 flags) {
    return verify(pkey, sig, input.data(), input.size(), signature, flags);
}

return_t openssl_sign::verify(const EVP_PKEY* pkey, signature_t sig, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto kty = ktyof_evp_pkey(pkey);

        const hint_signature_t* hint = advisor->hintof_signature(sig);
        if (nullptr == hint) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
        auto category = categoryof(hint);
        hash_algorithm_t hash_alg = typeof_alg(hint);

        switch (kty) {
            case kty_oct:
                switch (category) {
                    case sig_category_t::dgst:
                        ret = verify_digest(pkey, hash_alg, stream, size, signature);
                        break;
                    case sig_category_t::hmac:
                        ret = verify_hmac(pkey, hash_alg, stream, size, signature);
                        break;
                    default:
                        ret = errorcode_t::bad_request;
                        break;
                }
                break;
            case kty_rsa:
            case kty_rsapss:
                switch (category) {
                    case sig_category_t::rsassa_pkcs15:
                        ret = verify_rsassa_pkcs15(pkey, hash_alg, stream, size, signature);
                        break;
                    case sig_category_t::rsassa_pss:
                        ret = verify_rsassa_pss(pkey, hash_alg, stream, size, signature);
                        break;
                    default:
                        ret = errorcode_t::bad_request;
                        break;
                }
                break;
            case kty_ec:
                ret = verify_ecdsa(pkey, hash_alg, stream, size, signature, flags);
                break;
            case kty_okp:
                ret = verify_digestsign(pkey, stream, size, signature);
                break;
            case kty_dsa:
                ret = verify_dsa(pkey, hash_alg, stream, size, signature);
                break;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
            case kty_mldsa:
            case kty_slhdsa:
                ret = verify_mldsa(pkey, stream, size, signature);
                break;
#endif
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
