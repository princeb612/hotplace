/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/openssl_crypt.hpp>

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

        // nonce = constant | iv
        // constant to little-endian
        uint32 constant = 0;
        if (is_little_endian()) {
            constant = counter;
        } else {
            constant = convert_endian(counter);
        }

        if (nonce_size > 12) {
            nonce_size = 12;
        }

        iv.resize(4);
        memcpy(&iv[0], (byte_t *)&constant, sizeof(counter));
        iv.insert(iv.end(), nonce, nonce + nonce_size);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
