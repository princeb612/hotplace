/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_CRYPTO_TYPES__
#define __HOTPLACE_SDK_CRYPTO_CRYPTO_TYPES__

#include <sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

class crypto_aead;
class crypto_aead_builder;
class cipher_encrypt;
class cipher_encrypt_builder;
class crypto_encrypt;
class crypto_encrypt_builder;
class crypto_hash;
class crypto_hash_builder;
class crypto_hmac;
class crypto_hmac_builder;
class crypto_sign;
class crypto_sign_builder;
class transcript_hash;
class transcript_hash_builder;

}  // namespace crypto
}  // namespace hotplace

#endif
