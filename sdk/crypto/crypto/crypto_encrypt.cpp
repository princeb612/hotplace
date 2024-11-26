/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/crypto/crypto_encrypt.hpp>

namespace hotplace {
namespace crypto {

crypto_encrypt::crypto_encrypt(crypt_enc_t enc) : _enc(enc) { _shared.make_share(this); }

return_t crypto_encrypt::encrypt(const EVP_PKEY* pkey, const binary_t& plaintext, binary_t& ciphertext) {
    return encrypt(pkey, &plaintext[0], plaintext.size(), ciphertext);
}

return_t crypto_encrypt::encrypt(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& ciphertext) {
    return_t ret = errorcode_t::success;
    openssl_crypt crypt;
    ret = crypt.encrypt(pkey, stream, size, ciphertext, _enc);
    return ret;
}

return_t crypto_encrypt::decrypt(const EVP_PKEY* pkey, const binary_t& ciphertext, binary_t& plaintext) {
    return decrypt(pkey, &ciphertext[0], ciphertext.size(), plaintext);
}

return_t crypto_encrypt::decrypt(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& plaintext) {
    return_t ret = errorcode_t::success;
    openssl_crypt crypt;
    ret = crypt.decrypt(pkey, stream, size, plaintext, _enc);
    return ret;
}

crypto_encrypt_builder::crypto_encrypt_builder() : _enc(crypt_enc_undefined) {}

crypto_encrypt* crypto_encrypt_builder::build() {
    crypto_encrypt* obj = nullptr;
    __try_new_catch_only(obj, new crypto_encrypt(_enc));
    return obj;
}

crypto_encrypt_builder& crypto_encrypt_builder::set(crypt_enc_t enc) {
    _enc = enc;
    return *this;
}

}  // namespace crypto
}  // namespace hotplace
