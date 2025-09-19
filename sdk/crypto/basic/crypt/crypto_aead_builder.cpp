/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_aead.hpp>

namespace hotplace {
namespace crypto {

crypto_aead_builder::crypto_aead_builder() : _scheme(crypto_scheme_unknown) {}

crypto_aead* crypto_aead_builder::build() {
    crypto_aead* obj = nullptr;
    auto scheme = get_scheme();
    switch (scheme) {
        case crypto_scheme_aes_128_ccm:
        case crypto_scheme_aes_128_gcm:
        case crypto_scheme_aes_192_ccm:
        case crypto_scheme_aes_192_gcm:
        case crypto_scheme_aes_256_ccm:
        case crypto_scheme_aes_256_gcm:
        case crypto_scheme_aria_128_ccm:
        case crypto_scheme_aria_128_gcm:
        case crypto_scheme_aria_192_ccm:
        case crypto_scheme_aria_192_gcm:
        case crypto_scheme_aria_256_ccm:
        case crypto_scheme_aria_256_gcm:
        case crypto_scheme_camellia_128_gcm:
        case crypto_scheme_camellia_192_gcm:
        case crypto_scheme_camellia_256_gcm:
        case crypto_scheme_chacha20_poly1305:
        case crypto_scheme_tls_aes_128_ccm:
        case crypto_scheme_tls_aes_256_ccm:
        case crypto_scheme_tls_aes_128_ccm_8:
        case crypto_scheme_tls_aes_256_ccm_8:
        case crypto_scheme_tls_aes_128_gcm:
        case crypto_scheme_tls_aes_256_gcm:
        case crypto_scheme_tls_chacha20_poly1305:
        case crypto_scheme_tls_aria_128_ccm:
        case crypto_scheme_tls_aria_256_ccm:
        case crypto_scheme_tls_aria_128_gcm:
        case crypto_scheme_tls_aria_256_gcm:
        case crypto_scheme_tls_camellia_128_gcm:
        case crypto_scheme_tls_camellia_256_gcm: {
            __try_new_catch_only(obj, new crypto_aead(scheme));
        } break;
        default: {
        } break;
    }
    return obj;
}

crypto_scheme_t crypto_aead_builder::get_scheme() { return _scheme; }

crypto_aead_builder& crypto_aead_builder::set_scheme(crypto_scheme_t scheme) {
    _scheme = scheme;
    return *this;
}

}  // namespace crypto
}  // namespace hotplace
