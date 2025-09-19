/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/cipher_encrypt.hpp>

namespace hotplace {
namespace crypto {

cipher_encrypt::cipher_encrypt(crypt_algorithm_t alg, crypt_mode_t mode) : _alg(alg), _mode(mode) { _shared.make_share(this); }

return_t cipher_encrypt::encrypt(const binary_t& key, const binary_t& iv, const binary_t& plaintext, binary_t& ciphertext) {
    return encrypt(key, iv, &plaintext[0], plaintext.size(), ciphertext);
}

return_t cipher_encrypt::encrypt(const binary_t& key, const binary_t& iv, const byte_t* stream, size_t size, binary_t& ciphertext) {
    return_t ret = errorcode_t::success;
    openssl_crypt crypt;
    crypt_context_t* handle = nullptr;
    ret = crypt.open(&handle, _alg, _mode, key, iv);
    if (errorcode_t::success == ret) {
        ret = crypt.encrypt(handle, stream, size, ciphertext);
        crypt.close(handle);
    }
    return ret;
}

return_t cipher_encrypt::decrypt(const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext) {
    return decrypt(key, iv, &ciphertext[0], ciphertext.size(), plaintext);
}

return_t cipher_encrypt::decrypt(const binary_t& key, const binary_t& iv, const byte_t* stream, size_t size, binary_t& plaintext) {
    return_t ret = errorcode_t::success;
    openssl_crypt crypt;
    crypt_context_t* handle = nullptr;
    ret = crypt.open(&handle, _alg, _mode, key, iv);
    if (errorcode_t::success == ret) {
        ret = crypt.decrypt(handle, stream, size, plaintext);
        crypt.close(handle);
    }
    return ret;
}

void cipher_encrypt::addref() { _shared.addref(); }

void cipher_encrypt::release() { _shared.delref(); }

}  // namespace crypto
}  // namespace hotplace
