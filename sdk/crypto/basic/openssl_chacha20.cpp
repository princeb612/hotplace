/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7539 ChaCha20 and Poly1305 for IETF Protocols
 *  RFC 8439 ChaCha20 and Poly1305 for IETF Protocols
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/openssl_chacha20.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_chacha20_iv(binary_t& iv, uint32 counter, binary_t const& nonce) { return openssl_chacha20_iv(iv, counter, &nonce[0], nonce.size()); }

return_t openssl_chacha20_iv(binary_t& iv, uint32 counter, const byte_t* nonce, size_t nonce_size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == nonce) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        iv.resize(4);
        memcpy(&iv[0], (byte_t*)&counter, 4);

        iv.insert(iv.end(), nonce, nonce + nonce_size);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
