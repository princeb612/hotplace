/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/crypto/basic/openssl_crypt.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_chacha20_iv(binary_t &iv, uint32 counter, const binary_t &nonce) { return openssl_chacha20_iv(iv, counter, &nonce[0], nonce.size()); }

return_t openssl_chacha20_iv(binary_t &iv, uint32 counter, const byte_t *nonce, size_t nonce_size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == nonce) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (nonce_size > 12) {
            nonce_size = 12;
        }

        // nonce = constant | iv
        // constant is little-endian

        if (is_little_endian()) {
            binary_append(iv, counter);
        } else {
            binary_append(iv, convert_endian(counter));
        }
        binary_append(iv, nonce, nonce_size);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
