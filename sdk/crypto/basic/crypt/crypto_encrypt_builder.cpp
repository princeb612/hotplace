/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_encrypt.hpp>

namespace hotplace {
namespace crypto {

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
