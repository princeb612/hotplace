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
 * @example
 *          constexpr byte_t data_plain[] = "still a man hears what he wants to hear and disregards the rest";
 *          size_t size_plain = RTL_NUMBER_OF (data_plain);
 *
 *          openssl_crypt crypt;
 *          crypt_context_t* handle = nullptr;
 *          binary_t data_encrypted;
 *          binary_t data_decrypted;
 *
 *          // key
 *          binary_t key;
 *          key.resize (32);
 *          for (int i = 0; i < 32; i++) {
 *              key[i] = i;
 *          }
 *
 *          // initial vector
 *          byte_t nonce_source [12] = { 0, 0, 0, 0, 0, 0, 0, 0x4a, };
 *          binary_t iv;
 *          openssl_chacha20_iv (iv, 1, nonce_source, 12);
 *
 *          // stream cipher
 *          {
 *              crypt.open (&handle, crypt_algorithm_t::chacha20, crypt_mode_t::stream_cipher, &key[0], key.size (), &iv[0], iv.size ());
 *              crypt.encrypt (handle, data_plain, size_plain, data_encrypted);
 *              crypt.decrypt (handle, &data_encrypted[0], data_encrypted.size (), data_decrypted);
 *              crypt.close (handle);
 *          }
 *
 *          // AEAD
 *          {
 *              binary_t aad;
 *              binary_t tag;
 *              openssl_prng rand;
 *              rand.random (aad, 32);
 *              crypt.open (&handle, crypt_algorithm_t::chacha20, crypt_mode_t::stream_aead, &key[0], key.size (), &iv[0], iv.size ());
 *              crypt.encrypt2 (handle, data_plain, size_plain, data_encrypted, &aad, &tag);
 *              crypt.decrypt2 (handle, &data_encrypted[0], data_encrypted.size (), data_decrypted, &aad, &tag);
 *              crypt.close (handle);
 *          }
 */
return_t openssl_chacha20_iv (binary_t & iv, uint32 counter, binary_t const & nonce);
return_t openssl_chacha20_iv (binary_t & iv, uint32 counter, const byte_t* nonce, size_t nonce_size);

}
}  // namespace

#endif
