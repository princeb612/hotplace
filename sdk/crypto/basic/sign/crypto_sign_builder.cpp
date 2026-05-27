/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_sign_builder.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_sign.hpp>

namespace hotplace {
namespace crypto {

crypto_sign_builder::crypto_sign_builder() : _category(sig_category_t::dgst), _hashalg(hash_algorithm_t{}) {}

crypto_sign* crypto_sign_builder::build() {
    crypto_sign* obj = nullptr;
    __try2 {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        return_t ret = errorcode_t::success;
        switch (get_digest()) {
            case hash_algorithm_t::sha2_512_224:
            case hash_algorithm_t::sha2_512_256:
                ret = errorcode_t::not_supported;
                break;
            default:
                break;
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
#endif
        switch (get_category()) {
            case sig_category_t::dgst: {
                obj = new crypto_sign_digest(get_digest());
            } break;
            case sig_category_t::hmac: {
                obj = new crypto_sign_hmac(get_digest());
            } break;
            case sig_category_t::rsassa_pkcs15: {
                obj = new crypto_sign_rsa_pkcs1(get_digest());
            } break;
            case sig_category_t::rsassa_pss: {
                obj = new crypto_sign_rsa_pss(get_digest());
            } break;
            case sig_category_t::ecdsa: {
                obj = new crypto_sign_ecdsa(get_digest());
            } break;
            case sig_category_t::eddsa: {
                obj = new crypto_sign_eddsa();
            } break;
            case sig_category_t::dsa: {
                obj = new crypto_sign_dsa(get_digest());
            } break;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
            case sig_category_t::mldsa: {
                obj = new crypto_sign_mldsa();
            } break;
            case sig_category_t::slhdsa: {
                obj = new crypto_sign_slhdsa();
            } break;
#endif
            case sig_category_t::brainpool: {
                obj = new crypto_sign_ecdsa(get_digest());
            } break;
            case sig_category_t::rsassa_x931:  //
            default: {
            } break;
        }
        if (obj) {
            obj->set_category(get_category());
        }
    }
    __finally2 {}
    return obj;
}

sig_category_t crypto_sign_builder::get_category() { return _category; }

crypto_sign_builder& crypto_sign_builder::set_category(sig_category_t category) {
    _category = category;
    return *this;
}

crypto_sign_builder& crypto_sign_builder::set_tls_sign_scheme(tls_sigscheme_t scheme) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_sigscheme(scheme);
    if (hint) {
        set_category(hint->category).set_digest(hint->dgst);
    }
    return *this;
}

hash_algorithm_t crypto_sign_builder::get_digest() { return (hash_algorithm_t)_hashalg; }

crypto_sign_builder& crypto_sign_builder::set_digest(hash_algorithm_t hashalg) {
    _hashalg = hashalg;
    return *this;
}

crypto_sign_builder& crypto_sign_builder::set_digest(const char* hashalg) {
    auto advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_digest(hashalg);
    _hashalg = typeof_alg(hint);
    return *this;
}
crypto_sign_builder& crypto_sign_builder::set_digest(const std::string& hashalg) {
    auto advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_digest(hashalg);
    _hashalg = typeof_alg(hint);
    return *this;
}

crypto_sign_builder& crypto_sign_builder::set_scheme(jws_t type) {
    // jws_t jws_hs256, ...
    // signature_t signature_t::hs256
    auto advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_jose_signature(type);
    if (hint) {
        set_category(hint->category).set_digest(hint->alg);
    }
    return *this;
}

}  // namespace crypto
}  // namespace hotplace
