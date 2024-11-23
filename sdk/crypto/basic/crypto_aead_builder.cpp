/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_aead.hpp>

namespace hotplace {
namespace crypto {

crypto_aead_builder::crypto_aead_builder() : _scheme(aead_scheme_unknown) {}

crypto_aead* crypto_aead_builder::build() {
    crypto_aead* obj = nullptr;
    switch (get_scheme()) {
        case aead_scheme_aes128_gcm: {
            obj = new crypto_aead_aes128gcm;
        } break;
        case aead_scheme_aes192_gcm: {
            obj = new crypto_aead_aes192gcm;
        } break;
        case aead_scheme_aes256_gcm: {
            obj = new crypto_aead_aes256gcm;
        } break;
        case aead_scheme_aes128_ccm: {
            obj = new crypto_aead_aes128ccm;
        } break;
        case aead_scheme_aes192_ccm: {
            obj = new crypto_aead_aes192ccm;
        } break;
        case aead_scheme_aes256_ccm: {
            obj = new crypto_aead_aes256ccm;
        } break;
        case aead_scheme_aes128_ccm8: {
            obj = new crypto_aead_aes128ccm8;
        } break;
        case aead_scheme_aes192_ccm8: {
            obj = new crypto_aead_aes192ccm8;
        } break;
        case aead_scheme_aes256_ccm8: {
            obj = new crypto_aead_aes128ccm8;
        } break;
        case aead_scheme_chacha20_poly1305: {
            obj = new crypto_aead_chacha20_poly1305;
        } break;
        case aead_scheme_aes128_cbc_hmac_sha2: {
        } break;
        case aead_scheme_aes192_cbc_hmac_sha2: {
        } break;
        case aead_scheme_aes256_cbc_hmac_sha2: {
        } break;
    }
    return obj;
}

crypto_aead_scheme_t crypto_aead_builder::get_scheme() { return _scheme; }

crypto_aead_builder& crypto_aead_builder::set_scheme(crypto_aead_scheme_t scheme) {
    _scheme = scheme;
    return *this;
}

}  // namespace crypto
}  // namespace hotplace
