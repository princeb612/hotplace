/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/crypto/cipher_encrypt.hpp>

namespace hotplace {
namespace crypto {

cipher_encrypt_builder::cipher_encrypt_builder() : _alg(crypt_alg_unknown), _mode(crypt_mode_unknown) {}

cipher_encrypt* cipher_encrypt_builder::build() {
    cipher_encrypt* obj = nullptr;
    __try_new_catch_only(obj, new cipher_encrypt(_alg, _mode));
    return obj;
}

cipher_encrypt_builder& cipher_encrypt_builder::set(crypt_algorithm_t alg, crypt_mode_t mode) {
    _alg = alg;
    _mode = mode;
    return *this;
}

}  // namespace crypto
}  // namespace hotplace
