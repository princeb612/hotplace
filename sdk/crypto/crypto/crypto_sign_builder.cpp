/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/crypto/crypto_sign.hpp>

namespace hotplace {
namespace crypto {

crypto_sign_builder::crypto_sign_builder() : _scheme(sign_scheme_unknown), _hashalg(0) {}

crypto_sign* crypto_sign_builder::build() {
    crypto_sign* obj = nullptr;
    switch (get_scheme()) {
        case sign_scheme_rsa_pkcs1: {
            obj = new crypto_sign_rsa_pkcs1(get_digest());
        } break;
        case sign_scheme_rsa_pss: {
            obj = new crypto_sign_rsa_pss(get_digest());
        } break;
        case sign_scheme_ecdsa: {
            obj = new crypto_sign_ecdsa(get_digest());
        } break;
        case sign_scheme_eddsa: {
            obj = new crypto_sign_eddsa(get_digest());
        } break;
    }
    return obj;
}

crypto_sign_scheme_t crypto_sign_builder::get_scheme() { return _scheme; }

crypto_sign_builder& crypto_sign_builder::set_scheme(crypto_sign_scheme_t scheme) {
    _scheme = scheme;
    return *this;
}

crypto_sign_builder& crypto_sign_builder::tls_sign_scheme(uint16 scheme) {
    switch (scheme) {
        case 0x0401: /* rsa_pkcs1_sha256 */ {
            set_scheme(sign_scheme_rsa_pkcs1).set_digest(sha2_256);
        } break;
        case 0x0501: /* rsa_pkcs1_sha384 */ {
            set_scheme(sign_scheme_rsa_pkcs1).set_digest(sha2_384);
        } break;
        case 0x0601: /* rsa_pkcs1_sha512 */ {
            set_scheme(sign_scheme_rsa_pkcs1).set_digest(sha2_512);
        } break;
        case 0x0403: /* ecdsa_secp256r1_sha256 */ {
            set_scheme(sign_scheme_ecdsa).set_digest(sha2_256);
        } break;
        case 0x0503: /* ecdsa_secp384r1_sha384 */ {
            set_scheme(sign_scheme_ecdsa).set_digest(sha2_384);
        } break;
        case 0x0603: /* ecdsa_secp521r1_sha512 */ {
            set_scheme(sign_scheme_ecdsa).set_digest(sha2_512);
        } break;
        case 0x0804: /* rsa_pss_rsae_sha256 */ {
            set_scheme(sign_scheme_rsa_pss).set_digest(sha2_256);
        } break;
        case 0x0805: /* rsa_pss_rsae_sha384 */ {
            set_scheme(sign_scheme_rsa_pss).set_digest(sha2_384);
        } break;
        case 0x0806: /* rsa_pss_rsae_sha512 */ {
            set_scheme(sign_scheme_rsa_pss).set_digest(sha2_512);
        } break;
        case 0x0807: /* ed25519 */ {
            set_scheme(sign_scheme_eddsa);
        } break;
        case 0x0808: /* ed448 */ {
            set_scheme(sign_scheme_eddsa);
        } break;
        case 0x0809: /* rsa_pss_pss_sha256 */ {
        } break;
        case 0x080a: /* rsa_pss_pss_sha384 */ {
        } break;
        case 0x080b: /* rsa_pss_pss_sha512 */ {
        } break;
        case 0x0201: /* rsa_pkcs1_sha1 */ {
            set_scheme(sign_scheme_rsa_pkcs1).set_digest(sha1);
        } break;
        case 0x0203: /* ecdsa_sha1 */ {
            set_scheme(sign_scheme_ecdsa).set_digest(sha1);
        } break;
    }
    return *this;
}

hash_algorithm_t crypto_sign_builder::get_digest() { return (hash_algorithm_t)_hashalg; }

crypto_sign_builder& crypto_sign_builder::set_digest(hash_algorithm_t hashalg) {
    _hashalg = hashalg;
    return *this;
}

}  // namespace crypto
}  // namespace hotplace
