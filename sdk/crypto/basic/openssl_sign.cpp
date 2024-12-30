/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>

namespace hotplace {
namespace crypto {

openssl_sign::openssl_sign() {
    // do nothing
}

openssl_sign::~openssl_sign() {
    // do nothing
}

return_t openssl_sign::sign(const EVP_PKEY* pkey, crypt_sig_t sig, const binary_t& input, binary_t& signature) {
    return sign(pkey, sig, &input[0], input.size(), signature);
}

return_t openssl_sign::sign(const EVP_PKEY* pkey, crypt_sig_t sig, const byte_t* stream, size_t size, binary_t& signature) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        int type = EVP_PKEY_id(pkey);
        const hint_signature_t* hint = advisor->hintof_signature(sig);
        if (nullptr == hint) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
        int group = typeof_group(hint);
        hash_algorithm_t hash_alg = typeof_alg(hint);
        switch (type) {
            case EVP_PKEY_HMAC:
                switch (group) {
                    case crypt_sig_type_t::crypt_sig_dgst:
                        ret = sign_digest(pkey, hash_alg, stream, size, signature);
                        break;
                    case crypt_sig_type_t::crypt_sig_hmac:
                        ret = sign_hmac(pkey, hash_alg, stream, size, signature);
                        break;
                }
                break;
            case EVP_PKEY_RSA:
                switch (group) {
                    case crypt_sig_type_t::crypt_sig_rsassa_pkcs15:
                        ret = sign_rsassa_pkcs15(pkey, hash_alg, stream, size, signature);
                        break;
                    case crypt_sig_type_t::crypt_sig_rsassa_pss:
                        ret = sign_rsassa_pss(pkey, hash_alg, stream, size, signature);
                        break;
                    default:
                        ret = errorcode_t::bad_request;
                        break;
                }
                break;
            case EVP_PKEY_EC:
                ret = sign_ecdsa(pkey, hash_alg, stream, size, signature);
                break;
            case EVP_PKEY_ED25519:
            case EVP_PKEY_ED448:
                ret = sign_eddsa(pkey, hash_alg, stream, size, signature);
                break;
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_sign::verify(const EVP_PKEY* pkey, crypt_sig_t sig, const binary_t& input, const binary_t& signature) {
    return verify(pkey, sig, &input[0], input.size(), signature);
}

return_t openssl_sign::verify(const EVP_PKEY* pkey, crypt_sig_t sig, const byte_t* stream, size_t size, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        int type = EVP_PKEY_id(pkey);
        const hint_signature_t* hint = advisor->hintof_signature(sig);
        if (nullptr == hint) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
        int group = typeof_group(hint);
        hash_algorithm_t hash_alg = typeof_alg(hint);
        switch (type) {
            case EVP_PKEY_HMAC:
                switch (group) {
                    case crypt_sig_type_t::crypt_sig_dgst:
                        ret = verify_digest(pkey, hash_alg, stream, size, signature);
                        break;
                    case crypt_sig_type_t::crypt_sig_hmac:
                        ret = verify_hmac(pkey, hash_alg, stream, size, signature);
                        break;
                }
                break;
            case EVP_PKEY_RSA:
                switch (group) {
                    case crypt_sig_type_t::crypt_sig_rsassa_pkcs15:
                        ret = verify_rsassa_pkcs15(pkey, hash_alg, stream, size, signature);
                        break;
                    case crypt_sig_type_t::crypt_sig_rsassa_pss:
                        ret = verify_rsassa_pss(pkey, hash_alg, stream, size, signature);
                        break;
                    default:
                        ret = errorcode_t::bad_request;
                        break;
                }
                break;
            case EVP_PKEY_EC:
                ret = verify_ecdsa(pkey, hash_alg, stream, size, signature);
                break;
            case EVP_PKEY_ED25519:
            case EVP_PKEY_ED448:
                ret = verify_eddsa(pkey, hash_alg, stream, size, signature);
                break;
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
