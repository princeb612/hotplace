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
#include <sdk/crypto/basic/crypto_aead.hpp>

namespace hotplace {
namespace crypto {

crypto_aead::crypto_aead(crypto_scheme_t scheme) : _scheme(scheme) { _shared.make_share(this); }

crypto_scheme_t crypto_aead::get_scheme() { return _scheme; }

void crypto_aead::addref() { _shared.addref(); }

void crypto_aead::release() { _shared.delref(); }

return_t crypto_aead::encrypt(const binary_t& key, const binary_t& iv, const binary_t& plaintext, binary_t& ciphertext, const binary_t& aad, binary_t& tag) {
    return encrypt(key, iv, &plaintext[0], plaintext.size(), ciphertext, aad, tag);
}

return_t crypto_aead::encrypt(const binary_t& key, const binary_t& iv, const unsigned char* stream, size_t size, binary_t& ciphertext, const binary_t& aad,
                              binary_t& tag) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == stream) && size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto hint_cipher = advisor->hintof_cipher(get_scheme());

        openssl_crypt crypt;
        encrypt_option_t options[] = {{crypt_ctrl_nsize, hint_cipher->nsize}, {crypt_ctrl_tsize, hint_cipher->tsize}, {}};

        ret = crypt.encrypt(typeof_alg(hint_cipher), typeof_mode(hint_cipher), key, iv, stream, size, ciphertext, aad, tag, options);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_aead::decrypt(const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext, const binary_t& aad,
                              const binary_t& tag) {
    return decrypt(key, iv, &ciphertext[0], ciphertext.size(), plaintext, aad, tag);
}

return_t crypto_aead::decrypt(const binary_t& key, const binary_t& iv, const unsigned char* stream, size_t size, binary_t& plaintext, const binary_t& aad,
                              const binary_t& tag) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == stream) && size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto hint_cipher = advisor->hintof_cipher(get_scheme());

        openssl_crypt crypt;
        encrypt_option_t options[] = {{crypt_ctrl_nsize, hint_cipher->nsize}, {crypt_ctrl_tsize, hint_cipher->tsize}, {}};

        ret = crypt.decrypt(typeof_alg(hint_cipher), typeof_mode(hint_cipher), key, iv, stream, size, plaintext, aad, tag, options);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
