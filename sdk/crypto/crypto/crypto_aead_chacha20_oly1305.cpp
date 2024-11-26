/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/crypto/crypto_aead.hpp>

namespace hotplace {
namespace crypto {

crypto_aead_chacha20_poly1305::crypto_aead_chacha20_poly1305() : crypto_aead(aead_scheme_chacha20_poly1305) {}

return_t crypto_aead_chacha20_poly1305::encrypt(const binary_t& key, const binary_t& nonce, const binary_t& plaintext, binary_t& ciphertext,
                                                const binary_t& aad, binary_t& tag) {
    return encrypt(key, nonce, &plaintext[0], plaintext.size(), ciphertext, aad, tag);
}

return_t crypto_aead_chacha20_poly1305::encrypt(const binary_t& key, const binary_t& nonce, const unsigned char* stream, size_t size, binary_t& ciphertext,
                                                const binary_t& aad, binary_t& tag) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_crypt crypt;
        ret = crypt.encrypt("chacha20-poly1305", key, nonce, stream, size, ciphertext, aad, tag);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_aead_chacha20_poly1305::decrypt(const binary_t& key, const binary_t& nonce, const binary_t& ciphertext, binary_t& plaintext,
                                                const binary_t& aad, const binary_t& tag) {
    return decrypt(key, nonce, &ciphertext[0], ciphertext.size(), plaintext, aad, tag);
}

return_t crypto_aead_chacha20_poly1305::decrypt(const binary_t& key, const binary_t& nonce, const unsigned char* stream, size_t size, binary_t& plaintext,
                                                const binary_t& aad, const binary_t& tag) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_crypt crypt;
        ret = crypt.decrypt("chacha20-poly1305", key, nonce, stream, size, plaintext, aad, tag);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
