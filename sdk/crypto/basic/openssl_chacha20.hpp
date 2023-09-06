/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_CHACHA20__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_CHACHA20__

#include <hotplace/sdk/crypto/types.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief   EVP_chacha20
 * @desc
 *          key 256bits (32bytes)
 *          iv 96bits (12bytes)
 *          https://www.openssl.org/docs/man1.1.1/man3/EVP_chacha20.html
 *          openssl iv 128bites (16bytes) = counter 32bits(LE) + iv 96bits
 *
 *          cf.
 *          https://www.openssl.org/docs/man3.0/man3/EVP_chacha20.html
 *          openssl iv 128bites (16bytes) = counter 64bits(LE) + iv 64bits - don't meet specifications
 */
return_t openssl_chacha20_iv (binary_t & iv, uint32 counter, binary_t const & nonce);
return_t openssl_chacha20_iv (binary_t & iv, uint32 counter, const byte_t* nonce, size_t nonce_size);

}
}  // namespace

#endif
